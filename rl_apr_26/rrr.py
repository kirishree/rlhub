import os
print(os.getenv("SECRET_KEY_JWT", "fallback-secret-key"))
