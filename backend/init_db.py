from database import get_db_connection
import os

def initialize_database():
    conn = get_db_connection()
    if conn is None:
        print("Failed to connect to DB. Is Docker running?")
        return

    try:
        cur = conn.cursor()
        
        # Read the schema.sql file
        schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
        with open(schema_path, 'r') as file:
            schema_sql = file.read()
            
        # Execute the SQL commands
        cur.execute(schema_sql)
        conn.commit()
        
        print("Database tables created successfully!")
        
    except Exception as e:
        print(f"Error creating tables: {e}")
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    initialize_database()