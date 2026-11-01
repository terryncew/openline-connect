"""Example seller-owned transactional business action. Only the same SQLite DB is atomic.
External ERP calls cannot be made exactly-once by this local adapter.
"""
class SqliteLocalAction:
    def install(self, db):
        db.execute('''CREATE TABLE IF NOT EXISTS business_jobs (
            buyer TEXT NOT NULL, po TEXT NOT NULL, sku TEXT NOT NULL,
            units INTEGER NOT NULL, amount_cents INTEGER NOT NULL,
            PRIMARY KEY (buyer,po))''')
    def commit(self, db, order):
        """Called inside Seller's BEGIN IMMEDIATE transaction. Must use same db connection.
        Raise on any failure to roll back decision and local order together.
        Production external systems need a durable outbox + idempotent consumer.
        """
        db.execute('''INSERT INTO business_jobs VALUES (?,?,?,?,?)''',
                   (order['buyer'],order['po'],order['sku'],order['units'],order['total_cents']))
