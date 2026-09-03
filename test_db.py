from database.connection import Database

result = Database.fetch_one("SELECT version();")

print(result)