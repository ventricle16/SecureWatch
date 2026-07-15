from backend.app import app, initialize_database

# Ensure database tables and seed data are initialized before serving.
initialize_database()

application = app
