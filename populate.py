from google.cloud import datastore

USERS = "users"

client = datastore.Client()  # move this to the top, outside the function

def populate_users():
    users = [
        {'sub': 'auth0|6a0e11ae5ca6737d2af5406b', 'role': 'admin'},
        {'sub': 'auth0|6a0e11bebf725ad312e51dda', 'role': 'instructor'},
        {'sub': 'auth0|6a0e11c75ca6737d2af5408a', 'role': 'instructor'},
        {'sub': 'auth0|6a0e11d2cfd8838127ad6546', 'role': 'student'},
        {'sub': 'auth0|6a0e11df5ca6737d2af540a3', 'role': 'student'},
        {'sub': 'auth0|6a0e12025ca6737d2af540cb', 'role': 'student'},
        {'sub': 'auth0|6a0e12105ca6737d2af540dc', 'role': 'student'},
        {'sub': 'auth0|6a0e12200580365abf1fb3e6', 'role': 'student'},
        {'sub': 'auth0|6a0e122c0580365abf1fb3fa', 'role': 'student'},
    ]
    for user in users:
        key = client.key(USERS)
        entity = datastore.Entity(key=key)
        entity.update(user)
        client.put(entity)
        print(f"Added user {user['sub']} with key ID: {entity.key.id}")  # helpful to see the generated IDs

if __name__ == '__main__':
    print("populating database")
    populate_users()