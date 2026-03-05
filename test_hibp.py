import pyhibp
from pyhibp import pwnedpasswords

try:
    pyhibp.set_user_agent(ua="Fraud_App_Teste")
    # pwnedpasswords API expects a User-Agent set.
    res = pwnedpasswords.is_password_breached(password="senha123")
    print(f"Breaches para 'senha123': {res}")
except Exception as e:
    print(f"API Error: {e}")
