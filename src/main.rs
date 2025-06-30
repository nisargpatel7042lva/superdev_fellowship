mod models;
mod handlers;
mod routes;

use routes::create_application_router;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = create_application_router();

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Solana Blockchain Server starting up...");
    println!("Server is now running on http://localhost:3000");
    println!("Ready to accept blockchain operations requests");

    axum::serve(listener, app).await.unwrap();
}
