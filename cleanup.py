from google.cloud import datastore

client = datastore.Client()
query = client.query(kind='users')
keys = [entity.key for entity in query.fetch()]
client.delete_multi(keys)
print(f"Deleted {len(keys)} entities")