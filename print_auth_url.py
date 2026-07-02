from gmail_auth import _default_client

client = _default_client()
url = f"https://accounts.google.com/o/oauth2/auth?client_id={client['client_id']}&redirect_uri=http%3A//localhost%3A8085/callback&scope=https%3A//www.googleapis.com/auth/gmail.readonly&response_type=code&access_type=offline&prompt=consent&login_hint=isiemaillo@gmail.com"
print(url)