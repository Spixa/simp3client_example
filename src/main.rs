use aes_gcm::Aes256Gcm;
use core::f32;
use eframe::egui;
use egui::Color32;
use net::{decode_packet, encode_packet};
use rs_sha512::HasherContext;
use rs_sha512::Sha512State;
use stcp::{AesPacket, bincode, client_kex};
use std::hash::BuildHasher;
use std::io::ErrorKind;
use std::net::Shutdown;
use std::process;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::{
    hash::Hasher,
    io::{Read, Write},
    net::TcpStream,
    sync::{
        Arc, RwLock,
        mpsc::{self, Sender, TryRecvError},
    },
    thread,
    time::Duration,
};
use types::{MSG_SIZE, Packet};

#[derive(Default)]
struct ChatClient {
    username: String,
    password: String,
    input: String,
    connected: bool,
    messages: Arc<RwLock<Vec<String>>>,
    server: ServerInfo,
    ui_theme: Theme,
    remote: Remote,
    running: Arc<AtomicBool>,
}

#[derive(Default)]
struct Remote {
    io: Option<Io>,
    aes: Option<Aes256Gcm>,
}

struct Io {
    tx: Sender<String>,
}

#[derive(Default)]
struct ServerInfo {
    _name: String,
    ip: String,
    _port: u16,
}

#[derive(Clone, Default)]
struct Theme {
    // bg_color: egui::Color32,
    // text_color: egui::Color32,
    // button_color: egui::Color32,
    // border_color: egui::Color32,
}

// Will be later:
// impl Default for Theme {
//     fn default() -> Self {
//         Self {
//             // shitty theme for now
//             // bg_color: egui::Color32::from_rgb(40, 40, 40),
//             // text_color: egui::Color32::from_rgb(200, 200, 200),
//             // button_color: egui::Color32::from_rgb(0, 100, 180),
//             // border_color: egui::Color32::from_rgb(203, 75, 22),
//         }
//     }
// }

impl ChatClient {
    fn send_message(&mut self) {
        if !self.input.trim().is_empty() {
            // message is good
            let msg = format!("<{}> {}", self.username, self.input);

            self.messages.write().unwrap().push(msg);

            self.remote
                .io
                .as_mut()
                .unwrap()
                .tx
                .send(self.input.clone())
                .expect("Failed to send over to receiver mpsc channel");

            self.input.clear();
        }
    }

    fn apply_theme(&self, ctx: &egui::Context) {
        // No style for now
        ctx.set_style(ctx.style());

        // get rid of pesky warning of unused code i hate it
        let _ = self.ui_theme.clone();
    }
}

impl eframe::App for ChatClient {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame /* Unnecessary */) {
        if !self.running.load(Ordering::Relaxed) {
            process::exit(0);
        }

        self.apply_theme(ctx);

        egui::CentralPanel::default().show(ctx, |ui| {
            if !self.connected {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    ui.label(egui::RichText::new("SIMP3 RUST CLIENT EXAMPLE").heading());

                    ui.add_space(30.0);

                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.username).hint_text("Username"),
                        );

                        ui.add(
                            egui::TextEdit::singleline(&mut self.password)
                                .hint_text("Password")
                                .password(true),
                        );

                        ui.add(
                            egui::TextEdit::singleline(&mut self.server.ip)
                                .hint_text("Server (IP:Port)"),
                        );
                    });

                    ui.add_space(15.0);

                    if ui.button("CONNECT").clicked() {
                        let mut stream = TcpStream::connect(self.server.ip.clone().trim())
                            .expect("Stream failed to connect");
                        self.remote.aes = match client_kex(&mut stream) {
                            Ok(v) => Some(v),
                            Err(e) => {
                                eprintln!("error occured during kex, dying (err: {e})");
                                std::process::exit(-1);
                            }
                        };

                        // Create password hash
                        let mut phrase_hash = Sha512State::default().build_hasher();
                        phrase_hash.write(&self.password.bytes().collect::<Vec<u8>>()[..]);
                        let phrase_hash = HasherContext::finish(&mut phrase_hash);

                        // Authenticate
                        let buf = encode_packet(Packet::Auth(
                            self.username.clone(),
                            format!("{phrase_hash:02x}"),
                        ));
                        let enc =
                            AesPacket::encrypt_to_bytes(self.remote.aes.as_mut().unwrap(), buf);

                        stream
                            .write_all(&enc)
                            .expect("initial auth failed (after kex succeeded)");

                        let (tx, rx) = mpsc::channel::<String>();
                        self.remote.io = Some(Io { tx });

                        stream.set_nonblocking(true).expect("Failed to set non-blocking to true");

                        // Required clones for thread:
                        let mvec_clone = self.messages.clone();
                        let mut aes_clone = self.remote.aes.clone().unwrap();
                        let running = self.running.clone();

                        thread::spawn(move || {
                            while running.load(Ordering::Relaxed) {
                                let mut buff = [0_u8; MSG_SIZE];

                                match stream.read(&mut buff) {
                                    Ok(size) => {
                                        let packet =
                                            bincode::deserialize::<AesPacket>(&buff[..size]);

                                        match packet {
                                            Ok(_) => {}
                                            Err(ref e) => {
                                                println!("server went down");
                                                println!("error: {e}");
                                                stream.shutdown(Shutdown::Both).expect("Failed to shutdown");
                                                running.store(false, Ordering::Relaxed);

                                                thread::sleep(Duration::from_secs(1));
                                            }
                                        }

                                        let packet = packet.unwrap();
                                        let decrypted = packet.decrypt(&mut aes_clone);
                                        let packet = decode_packet(&decrypted);

                                        // finally we have the packet
                                        match packet {
                                            Packet::Message(content, username, channel) => {
                                                mvec_clone.write().unwrap().push(format!(
                                                    "[{channel}] <{username}>: {content}"
                                                ));
                                            }
                                            Packet::ClientDM(_, _) => todo!(),
                                            Packet::Join(name) => {
                                                mvec_clone
                                                    .write()
                                                    .unwrap()
                                                    .push(format!("{name} joined the server"));
                                            }
                                            Packet::Leave(name) => {
                                                mvec_clone
                                                    .write()
                                                    .unwrap()
                                                    .push(format!("{name} left the server"));
                                            }
                                            Packet::ClientRespone(msg) => {
                                                mvec_clone
                                                    .write()
                                                    .unwrap()
                                                    .push(msg);
                                            }
                                            Packet::ServerDM(msg) => {
                                                mvec_clone
                                                    .write()
                                                    .unwrap()
                                                    .push(format!("[Server] {msg}"));
                                            }
                                            Packet::Broadcast(msg) => {
                                                mvec_clone
                                                    .write()
                                                    .unwrap()
                                                    .push(format!("[Server] {msg}"));
                                            }
                                            Packet::ChannelJoin(name, channel) => {
                                                mvec_clone
                                                    .write()
                                                    .unwrap()
                                                    .push(format!("{name} joined #{channel}"));
                                            }
                                            Packet::ChannelLeave(name, channel) => {
                                                mvec_clone
                                                    .write()
                                                    .unwrap()
                                                    .push(format!("{name} left #{channel}"));
                                            }
                                            _ => panic!("{}", "Recv Illegal packet"),
                                        }
                                    }
                                    Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
                                    Err(_) => {
                                        println!("connection with server was severed");
                                        break;
                                    }
                                }

                                match rx.try_recv() {
                                    Ok(msg) => {
                                        let packet = if msg.starts_with("/dm") {
                                            if msg.len() >= 4 {
                                                let dm_cmd = msg[4..].to_string();
                                                let (user, cont) = dm_cmd.split_once(' ').unwrap_or((dm_cmd.as_str(), ""));
                                                Packet::ClientDM(user.to_string(), cont.to_string())
                                            } else {
                                                println!("[client] internal command for DM is: /dm <uname> <content>");
                                                Packet::Ping
                                            }
                                        } else if msg.starts_with("/") {
                                            // Everything else will be a "server-side" command
                                            Packet::ServerCommand(msg)
                                        } else {
                                            Packet::ClientMessage(msg)
                                        };

                                        let buf = encode_packet(packet);
                                        let enc = AesPacket::encrypt_to_bytes(&mut aes_clone, buf);

                                        stream.write_all(&enc).expect("writing to socket failed");
                                    }
                                    Err(TryRecvError::Empty) => thread::yield_now(),
                                    Err(TryRecvError::Disconnected) => break,
                                }
                                thread::sleep(Duration::from_micros(50));
                            }
                        });

                        self.connected = true;
                    }
                });
            } else {
                egui::TopBottomPanel::top("header").show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("simp3 test client").heading());
                        ui.label(format!("Connected to: {}", self.server.ip));
                    });
                    ui.separator();
                });

                egui::SidePanel::left("channels")
                    .resizable(false)
                    .exact_width(150.0)
                    .show(ctx, |ui| {
                        ui.vertical(|ui| {
                            ui.label("CHANNELS");
                            ui.separator();

                            let channels = ["#general", "#lobby", "#random"];
                            for channel in channels {
                                if ui.button(channel).clicked() {
                                    self.messages
                                        .write()
                                        .unwrap()
                                        .push(format!("Joined {}", channel));
                                }
                            }
                        });
                    });

                egui::TopBottomPanel::bottom("logs").show(ctx, |ui| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        egui::ScrollArea::vertical()
                            .max_width(f32::INFINITY)
                            .max_height(ui.available_height() - 50.0)
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                for msg in self.messages.read().unwrap().iter() {
                                    ui.label(egui::RichText::new(msg).monospace());
                                }
                            });
                    });

                    // why the fuck isn't this in the bottom
                    egui::TopBottomPanel::bottom("input_panel").show_inside(ui, |ui| {
                        ui.horizontal(|ui| {
                            let text_edit = egui::TextEdit::singleline(&mut self.input)
                                .hint_text("Type your message...")
                                .text_color(Color32::from_rgb(255, 215, 0))
                                .desired_width(ui.available_width() - 200.0);

                            let id = ui.add(text_edit).id;
                            if ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                self.send_message();
                                ui.memory_mut(|mem| mem.request_focus(id)); // gain focus
                            }

                            if ui.button("Send").clicked() {
                                self.send_message();
                            }
                        });
                    });

                    egui::SidePanel::right("users")
                        .resizable(false)
                        .exact_width(120.0)
                        .show(ctx, |ui| {
                            ui.vertical(|ui| {
                                ui.label("USERS");
                                ui.separator();

                                let users = [
                                    ("spixa", egui::Color32::GREEN),
                                    ("kasraidk", egui::Color32::GREEN),
                                    ("ladyviviaen", egui::Color32::YELLOW),
                                    ("lef1n", egui::Color32::LIGHT_RED),
                                ];

                                for (user, color) in users {
                                    ui.horizontal(|ui| {
                                        ui.add(egui::Label::new(
                                            egui::RichText::new("●").color(color),
                                        ));
                                        ui.label(user);
                                    });
                                }
                            });
                        });
                });
            }
        });
    }
}

mod net;
mod types;

fn main() {
    let _ = eframe::run_native(
        "simp3_client",
        eframe::NativeOptions::default(),
        Box::new(|_creation_context| {
            Box::new(ChatClient {
                username: "spixa".into(),
                password: "1937".into(),
                server: ServerInfo {
                    _name: "simp3 server".into(),
                    ip: "localhost:37549".into(),
                    _port: 37549,
                },
                ui_theme: Theme::default(),
                input: "hello, world!".into(),
                connected: false,
                messages: Arc::new(RwLock::new(vec!["Welcome".into()])),
                remote: Remote::default(),
                running: Arc::new(AtomicBool::new(true)),
            })
        }),
    );
}
