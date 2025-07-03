mod models;
mod handlers;
mod routes;
mod json_extractor;

use routes::create_application_router;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = create_application_router();

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Solana Fellowship API server starting up...");
    println!("Server is now running on http://localhost:3000");
    println!("Ready to accept blockchain operations requests");

    axum::serve(listener, app).await.unwrap();
}
