use std::net::SocketAddr;

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;


mod proxy;


#[derive(Debug)]
enum ControlMsg {
    Shutdown
}

#[derive(Debug)]
enum TaskMsg {
    Add(SocketAddr, JoinHandle<()>),
    Remove(SocketAddr),
    AbortAll,
}

#[derive(Debug, Clone)]
struct Config {
    control_socket: String,
    proxy_socket: String,
}


#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {

    loop {
        println!("Server starting...");

        let cfg_ctl = Config {
            control_socket: String::from("127.0.0.1:8081"),
            proxy_socket: String::from("127.0.0.1:8080"),
        };

        let cfg = cfg_ctl.clone();

        let (tx, rx) = mpsc::channel::<ControlMsg>(1);
        

        let srv_control = tokio::spawn(serve_control(cfg_ctl, tx));
        let srv_proxy = serve_proxy(cfg, rx);

        let res = tokio::join!(srv_control, srv_proxy);

        if let (Ok(Ok(true)), Ok(_)) = res {
            continue;
        } else {
            break;
        }
    }

    Ok(())
}


async fn serve_control(cfg: Config, tx: mpsc::Sender<ControlMsg>) -> Result<bool, tokio::io::Error> {
    println!("Control socket is {}", cfg.control_socket);
    let control_lsn = TcpListener::bind(cfg.control_socket).await?;
    loop {
        match control_lsn.accept().await {
            Err(e) => {
                println!("Error accepting connection: {}", e);
                continue;
            },
            Ok((_stream, _addr)) => {
                // Shutdown
                println!("Shutting down...");
                tx.send(ControlMsg::Shutdown).await.unwrap();
                return Ok(false);
            }
        }
    }
}

async fn serve_proxy(cfg: Config, mut rx: mpsc::Receiver<ControlMsg>) -> Result<(), Box<dyn std::error::Error>> {
    println!("Proxy socket is {}", cfg.proxy_socket);
    let proxy_lsn = TcpListener::bind(cfg.proxy_socket).await.expect("Proxy: cannot bind to socket");

    let (tx_task, rx_task) = mpsc::channel::<TaskMsg>(32);
    let task_watcher = tokio::spawn(watch_tasks(rx_task));

    loop {
        tokio::select!(
            con = proxy_lsn.accept() => {
                match con {
                    Ok((stream, addr)) => {
                        let ttx = tx_task.clone();
                        let task = tokio::spawn(async move {
                            println!("Incoming connection from {}", addr);

                            if let Err(e) = proxy::handle_stream(stream).await {
                                println!("Error: {:?}", e);
                            }

                            println!("Closing connection {}", addr);
                            ttx.send(TaskMsg::Remove(addr)).await.unwrap();
                        });

                        tx_task.send(TaskMsg::Add(addr, task)).await.unwrap();
                    },
                    Err(e) => {
                        println!("Error accepting connection: {}", e);
                        continue;
                    },
                }
            }

            Some(msg) = rx.recv() => { 
                match msg {
                    ControlMsg::Shutdown => {
                        break;
                    }
                }
            }
        );
    }

    tx_task.send(TaskMsg::AbortAll).await.unwrap();
    task_watcher.await.unwrap();

    Ok(())
}


async fn watch_tasks(mut rx: mpsc::Receiver<TaskMsg>) {
    use std::collections::{HashMap, HashSet};
    let mut tasks: HashMap<SocketAddr, JoinHandle<()>> = HashMap::with_capacity(64);
    let mut pre_deleted: HashSet<SocketAddr> = HashSet::with_capacity(8);

    loop {
        if let Some(msg) = rx.recv().await {
            match msg {
                TaskMsg::Add(s, h) => {
                    if !pre_deleted.remove(&s) {
                        tasks.insert(s, h);
                    }
                },
                TaskMsg::Remove(s) => {
                    if tasks.remove(&s).is_none() {
                        pre_deleted.insert(s);
                    }
                },
                TaskMsg::AbortAll => {
                    break;
                }
            };
        } else {
            break;
        }
    }

    // abort existing tasks
    println!("Aborting {} tasks", tasks.len());
    for (_, t) in tasks.drain() {
        t.abort();
    }
}
