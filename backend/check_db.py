import psycopg2
conn = psycopg2.connect('postgresql://ulpf:your-local-password@localhost:5432/ulpf')
cur = conn.cursor()
cur.execute("SELECT raw_event_id FROM raw_object_metadata WHERE raw_event_id = 'bc1378f3-4ecc-405e-9f7f-99c829b7e413'")
print('raw_object_metadata:', cur.fetchall())
cur.execute("SELECT event_id, processing_status FROM event_metadata WHERE raw_event_id = 'bc1378f3-4ecc-405e-9f7f-99c829b7e413'")
print('event_metadata:', cur.fetchall())
conn.close()