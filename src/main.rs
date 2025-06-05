use aes_gcm::Aes256Gcm;
use chrono::{DateTime, Local};
use eframe::egui;
use egui::{Color32, Stroke};
use net::{decode_packet, encode_packet};
use rs_sha512::{HasherContext, Sha512State};
use stcp::{AesPacket, bincode, client_kex};
use std::{
    hash::{BuildHasher, Hasher},
    io::{ErrorKind, Read, Write},
    net::{Shutdown, TcpStream},
    process,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender, TryRecvError},
    },
    thread,
    time::Duration,
};
use types::{MSG_SIZE, Packet};

type MessageVec = Arc<RwLock<Vec<(String, egui::Color32, DateTime<Local>)>>>;

#[derive(Default)]
struct ChatClient {
    username: String,
    password: String,
    input: String,
    connected: bool,
    messages: MessageVec,
    users: Arc<RwLock<Vec<String>>>,
    server: ServerInfo,
    ui_theme: Theme,
    remote: Remote,
    running: Arc<AtomicBool>,
    repaint: Arc<AtomicBool>,
    error_modal: ErrorWindow,
}

#[derive(Default)]
struct ErrorWindow {
    show: bool,
    message: String,
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
    name: String,
    ip: String,
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
            // DEBUG
            // let msg = format!("<{}> {}", self.username, self.input);
            // self.messages.write().unwrap().push((msg, Color32::GRAY));

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
        let mut style = (*ctx.style()).clone();
        style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, Color32::from_gray(50));
        ctx.set_style(style);

        // get rid of pesky warning of unused code i hate it
        let _ = self.ui_theme.clone();
    }
}

impl eframe::App for ChatClient {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame /* Unnecessary */) {
        if !self.running.load(Ordering::Relaxed) {
            process::exit(0);
        }

        if self.repaint.load(Ordering::Relaxed) {
            ctx.request_repaint();
            self.repaint.store(true, Ordering::Relaxed);
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
                            egui::TextEdit::singleline(&mut self.username).hint_text("username"),
                        );

                        ui.add(
                            egui::TextEdit::singleline(&mut self.password)
                                .hint_text("password")
                                .password(true),
                        );

                        ui.separator();

                        ui.add(
                            egui::TextEdit::singleline(&mut self.server.name)
                                .hint_text("server name")
                        );

                        ui.add(
                            egui::TextEdit::singleline(&mut self.server.ip)
                                .hint_text("server (ip:port)"),
                        );
                    });

                    ui.add_space(15.0);

                    if ui.button("CONNECT").clicked() {
                        let mut stream = match TcpStream::connect(self.server.ip.clone().trim()) {
                            Ok(stream) => {
                                stream
                            },
                            Err(err) => {
                                self.error_modal.show = true;
                                self.error_modal.message = format!("Failed to connec to the server: (err {}) {}", err.raw_os_error().unwrap(), err.kind());
                                return;
                            }
                        };

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
                        let uvec_clone = self.users.clone();
                        let mut aes_clone = self.remote.aes.clone().unwrap();
                        let running = self.running.clone();
                        let repaint = self.repaint.clone();

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

                                        let now = Local::now();
                                        // finally we have the packet
                                        match packet {
                                            Packet::Message(content, username, channel) => {
                                                mvec_clone.write().unwrap().push((format!(
                                                    "[#{channel}] <{username}>: {content}"
                                                ), Color32::WHITE, now));
                                            }
                                            Packet::ClientDM(_, _) => todo!(),
                                            Packet::Join(name) => {
                                                mvec_clone
                                                    .write()
                                                    .unwrap()
                                                    .push( (format!("{name} joined the server"), Color32::YELLOW, now));
                                            }
                                            Packet::Leave(name) => {
                                                mvec_clone
                                                    .write()
                                                    .unwrap()
                                                    .push( (format!("{name} left the server"), Color32::YELLOW, now));
                                            }
                                            Packet::ClientRespone(msg) => {
                                                mvec_clone
                                                    .write()
                                                    .unwrap()
                                                    .push((msg, Color32::GRAY, now));
                                            }
                                            Packet::ServerDM(msg) => {
                                                mvec_clone
                                                    .write()
                                                    .unwrap()
                                                    .push( (format!("[Server] {msg}"), Color32::LIGHT_GREEN, now));
                                            }
                                            Packet::Broadcast(msg) => {
                                                mvec_clone
                                                    .write()
                                                    .unwrap()
                                                    .push( (format!("[Server] {msg}"), Color32::LIGHT_GREEN, now));
                                            }
                                            Packet::ChannelJoin(name, channel) => {
                                                mvec_clone
                                                    .write()
                                                    .unwrap()
                                                    .push( (format!("{name} joined #{channel}"), Color32::YELLOW, now) );
                                            }
                                            Packet::ChannelLeave(name, channel) => {
                                                mvec_clone
                                                    .write()
                                                    .unwrap()
                                                    .push( (format!("{name} left #{channel}"), Color32::YELLOW, now));
                                            }
                                            Packet::List(list) => {
                                                let members : Vec<&str> = list.split(',').collect();
                                                uvec_clone.write().unwrap().clear();
                                                println!("Got list!");
                                                dbg!(members.clone());
                                                for member in members {
                                                    uvec_clone.write().unwrap().push(member.to_owned());
                                                }
                                            }
                                            _ => panic!("{}", "Recv Illegal packet"),
                                        }
                                        repaint.store(true, Ordering::Relaxed);
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
                                //thread::sleep(Duration::from_micros(50000));
                            }
                        });

                        self.connected = true;
                    }

                    #[cfg(debug_assertions)]
                    if ui.button("QUICK FILL (DEBUG)").clicked() {
                        self.username = "debugger".into();
                        self.password = "1234".into();
                        self.server.name = "local debugging server".into();
                        self.server.ip = "127.0.0.1:37549".into();
                    }

                    if self.error_modal.show {
                        egui::Window::new(egui::RichText::new("Connection Error").color(Color32::WHITE))
                            .collapsible(false)
                            .resizable(false)
                            .anchor(egui::Align2::CENTER_CENTER, [0.0, -50.0])
                            .show(ctx, |ui| {
                                ui.label(egui::RichText::new(&self.error_modal.message).color(Color32::RED));
                                ui.separator();

                                ui.horizontal(|ui| {
                                    if ui.button(egui::RichText::new("Reset field").color(Color32::LIGHT_GRAY)).clicked() {
                                        self.error_modal.show = false;
                                        self.server.ip = "".into();
                                    }

                                    if ui.button(egui::RichText::new("Go back").color(Color32::LIGHT_GRAY)).clicked() {
                                        self.error_modal.show = false;
                                    }
                                });
                            });
                    }
                });
            } else {

                egui::TopBottomPanel::top("header").show(ctx, |ui| {
                    egui::menu::bar(ui, |ui| {
                        ui.menu_button("openSIMP3", |_ui| {

                        });
                        ui.menu_button("File", |_ui| {

                        });
                        ui.menu_button("View", |_ui| {

                        });
                        ui.menu_button("About", |_ui| {

                        });
                    });

                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("simp3 test client").color(Color32::GREEN).heading());
                        ui.label(format!("Connected to: {}", self.server.ip));
                    });
                });

                egui::SidePanel::left("channels")
                    .resizable(false)
                    .exact_width(150.0)
                    .show(ctx, |ui| {
                        ui.vertical(|ui| {
                            ui.label("CHANNELS");
                            ui.separator();

                            let channels = ["general", "lobby", "random"];
                            for channel in channels {
                                if ui.button(format!("#{channel}")).clicked() {
                                    self.input = format!("/join {channel}");
                                    self.send_message();
                                }
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

                            for user in self.users.read().unwrap().iter() {
                                ui.horizontal(|ui| {
                                    ui.add(egui::Label::new(
                                        egui::RichText::new("●").color(Color32::YELLOW),
                                    ));
                                    ui.label(user);
                                });
                            }
                        });
                });

                egui::TopBottomPanel::bottom("logs").show(ctx, |ui| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        egui::ScrollArea::vertical()
                            .max_height(ui.available_height() - 50.0)
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                //ui.set_max_height(max_width);
                                for (msg, color, time) in self.messages.read().unwrap().iter() {
                                    ui.horizontal(|ui| {
                                        // Timestamp in gray
                                        ui.label(
                                            egui::RichText::new(format!("{}  ", time.format("%H:%M:%S")))
                                                .color(egui::Color32::GRAY)
                                                .monospace()
                                        );

                                        // Message with original color
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(msg)
                                                    .text_style(egui::TextStyle::Monospace)
                                                    .color(*color)
                                            )
                                            .wrap(true)
                                        );
                                    });
                                }
                            });
                    });

                    egui::TopBottomPanel::bottom("input_panel").show_separator_line(false).show_inside(ui, |ui| {
                        ui.horizontal(|ui| {
                            let text_edit = egui::TextEdit::singleline(&mut self.input)
                                .hint_text("type your message...")
                                .text_color(Color32::from_rgb(255, 215, 0));

                            let response = ui.add_sized(
                                [ui.available_width() - 130.0, 24.0],
                                text_edit
                            );

                            // width is fixed
                            ui.add_sized([60.0, 24.0], egui::Button::new("Send"))
                                .clicked()
                                .then(|| self.send_message());

                            ui.add_sized([60.0, 24.0], egui::Button::new("Clear Logs"))
                                .clicked()
                                .then(|| self.messages.write().unwrap().clear());

                            // regain focus when we send
                            if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                self.send_message();
                                ui.memory_mut(|mem| mem.request_focus(response.id));
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
                username: "".into(),
                password: "".into(),
                server: ServerInfo {
                    name: "simp3 server".into(),
                    ip: "localhost:37549".into(),
                },
                ui_theme: Theme::default(),
                input: "hello, world!".into(),
                connected: false,
                messages: Arc::new(RwLock::new(vec![])),
                users: Arc::new(RwLock::new(vec![])),
                remote: Remote::default(),
                running: Arc::new(AtomicBool::new(true)),
                repaint: Arc::new(AtomicBool::new(false)),
                error_modal: ErrorWindow {
                    show: false,
                    message: "No error has occured".into(),
                },
            })
        }),
    );
}
