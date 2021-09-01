import hybrid
import pickle
import os
import csv


class SetupSubProtocol:
    
    def __init__(self, client, merchant):
        self.client = client
        self.merchant = merchant
    
    def start(self):
        self.step1()
        self.step2()

    def step1(self):
        # Client
        # criptam hibrid cheia publica a clientului cu cheia publica a vanzatorului si o trimitem lui
        self.client.set_aes_key()
        PubKC = self.client.public_key.exportKey()
        client_message_enc, aes_m_key_enc = hybrid.rsa_aes_hybrid_encryption(PubKC, self.client.merchant_public_key, self.client._aes_key)
        CLIENT_MESSAGE = (client_message_enc, aes_m_key_enc)
        PICKLE_CLIENT_MESSAGE = pickle.dumps(CLIENT_MESSAGE, pickle.HIGHEST_PROTOCOL)

        # Merchant
        # decriptam mesajul primit de la client si salvam cheia publica a clientului
        UNPICKLE_CLIENT_MESSAGE = pickle.loads(PICKLE_CLIENT_MESSAGE)
        m_client_message_enc, m_aes_m_key_enc = UNPICKLE_CLIENT_MESSAGE
        m_client_message_dec = hybrid.rsa_aes_hybrid_decryption(m_client_message_enc, self.merchant._private_key, m_aes_m_key_enc)
        self.merchant.client_public_key = hybrid.importKey(m_client_message_dec)
        self.merchant.client_aes_key = hybrid.rsa_decryption(m_aes_m_key_enc, self.merchant._private_key)

    def step2(self):
        # Merchant
        # generam Sid si SigM(Sid), le criptam cu cheia publica a clientului si i le trimitem
        self.merchant.generate_session_id()
        Sid = self.merchant.session_id
        SigM_Sid = hybrid.signature(Sid.encode()).hexdigest()
        merchant_message_struct = (Sid, SigM_Sid)
        pickled_merchant_message_struct = pickle.dumps(merchant_message_struct, pickle.HIGHEST_PROTOCOL)
        merchant_message_enc, aes_c_key_enc = hybrid.rsa_aes_hybrid_encryption(pickled_merchant_message_struct, self.merchant.client_public_key, self.merchant.client_aes_key)
        MERCHANT_MESSAGE = (merchant_message_enc, aes_c_key_enc)
        PICKLE_MERCHANT_MESSAGE = pickle.dumps(MERCHANT_MESSAGE, pickle.HIGHEST_PROTOCOL)

        # Client
        # verificam validitatea Sid
        UNPICKLE_MERCHANT_MESSAGE = pickle.loads(PICKLE_MERCHANT_MESSAGE)
        c_merchant_message_enc, c_aes_c_key_enc = UNPICKLE_MERCHANT_MESSAGE
        c_merchant_message_dec = hybrid.rsa_aes_hybrid_decryption(c_merchant_message_enc, self.client._private_key, c_aes_c_key_enc)
        c_Sid, c_SigMSid = pickle.loads(c_merchant_message_dec)
        self.client.session_id = c_Sid

        if hybrid.signature(c_Sid.encode()).hexdigest() != c_SigMSid:
            raise Exception("Step2 failed. Sid mismatch!")
        else:
            print("Step2: finished")


class ExchangeSubProtocol:

    def __init__(self, client, merchant, payment_gateway):
        self.client = client
        self.merchant = merchant
        self.payment_gateway = payment_gateway

    def start(self):
        self.step3()
        self.step4()
        self.step5()
        self.step6()

    def step3(self):
        self.merchant.list_products()
        OrderDesc, Amount = input("Enter Order (<product> <amount>): ").split(' ')

        # Client
        # PM = {PI, SigC(PI)}
        # PI = CardN, CardExp, CCode, Sid, Amount, PubKC, NC, M
        # banca genereaza CCode
        # preluam CardN, CardExp, Amount introduse de client
        self.payment_gateway.generate_challenge_code()
        print("[PaymentGateway] Challenge code: {}".format(self.payment_gateway.challenge_code))
        
        CardN = input("Card number: ")
        CardExp = input("Card exp (MM/YYYY): ")
        CCode = input("Challenge Code: ")
        Sid = self.client.session_id
        self.client.Amount = Amount
        PubKC = self.client.public_key.exportKey()
        self.client.generate_nonce()
        NC = self.client._nonce
        self.client.NC = NC
        M = self.merchant.id

        PI = (CardN, CardExp, CCode, Sid, Amount, PubKC, NC, M)
        pickle_PI = pickle.dumps(PI, pickle.HIGHEST_PROTOCOL)
        SigC_pickle_PI = hybrid.signature(pickle_PI).hexdigest()
        client_PI = (pickle_PI, SigC_pickle_PI)
        client_PI_pickled = pickle.dumps(client_PI, pickle.HIGHEST_PROTOCOL)

        client_PM_enc, aes_pg_key_enc = hybrid.rsa_aes_hybrid_encryption(client_PI_pickled, self.client.pg_public_key, self.client._aes_key)
        PM = (client_PM_enc, aes_pg_key_enc)
        PM_pickled = pickle.dumps(PM, pickle.HIGHEST_PROTOCOL)
        
        # PO = OrderDesc, Sid, Amount, NC, SigC(OrderDesc, Sid, Amount, NC)
        O = (OrderDesc, Sid, Amount, NC)
        pickle_O = pickle.dumps(O, pickle.HIGHEST_PROTOCOL)
        SigC_pickle_O = hybrid.signature(pickle_O).hexdigest()
        PO = (pickle_O, SigC_pickle_O)
        PO_pickled = pickle.dumps(PO, pickle.HIGHEST_PROTOCOL)

        
        # trimitem (PM, PO) criptat cu cheia publica a vanzatorului catre vanzator
        client_message_struct = (PM_pickled, PO_pickled)
        pickled_client_message_struct = pickle.dumps(client_message_struct, pickle.HIGHEST_PROTOCOL)
        client_message_enc, aes_c_key_enc = hybrid.rsa_aes_hybrid_encryption(pickled_client_message_struct, self.client.merchant_public_key, self.client._aes_key)
        CLIENT_MESSAGE = (client_message_enc, aes_c_key_enc)
        PICKLE_CLIENT_MESSAGE = pickle.dumps(CLIENT_MESSAGE, pickle.HIGHEST_PROTOCOL)

        # Merchant
        # vanzatorul verifica PO-ul + trimite catre PG celelalte detalii daca totul este in regula
        UNPICKLE_CLIENT_MESSAGE = pickle.loads(PICKLE_CLIENT_MESSAGE)
        m_client_message_enc, m_aes_c_key_enc = UNPICKLE_CLIENT_MESSAGE
        m_client_message_dec = hybrid.rsa_aes_hybrid_decryption(m_client_message_enc, self.merchant._private_key, m_aes_c_key_enc)
        m_PM_pickled, m_PO_pickled = pickle.loads(m_client_message_dec)

        # vanzatorul verifica PO si va trimite PM catre banca
        m_PO = pickle.loads(m_PO_pickled)
        m_pickle_O, m_SigC_pickle_O = m_PO
        if hybrid.signature(m_pickle_O).hexdigest() != m_SigC_pickle_O:
            raise Exception("Step3 failed. PO mismatch!")
        else:
            print("Step3: PO matched")

        m_unpickle_PO = pickle.loads(m_pickle_O)
        if self.merchant.is_order_ok(m_unpickle_PO):
            print("Step3: finished")
        else:
            raise Exception("Step3: order is not valid!")
        self.merchant.PO = m_unpickle_PO
        self.merchant.PM = m_PM_pickled

    def step4(self):
        # Merchant
        # vanzatorul trimite (PM, SigM(Sid, PubKC, Amount)) criptat cu cheia publica a bancii catre PaymentGateway
        PM = self.merchant.PM
        Sid = self.merchant.session_id
        PubKC = self.merchant.client_public_key.exportKey()
        Amount = self.merchant.PO[2]
        
        sigM_structure = (Sid, PubKC, Amount)
        pickle_sigM_structure = pickle.dumps(sigM_structure, pickle.HIGHEST_PROTOCOL)
        sigM = hybrid.signature(pickle_sigM_structure).hexdigest()
        merchant_message_struct = (PM, sigM)
        pickle_merchant_message_struct = pickle.dumps(merchant_message_struct, pickle.HIGHEST_PROTOCOL)
        merchant_message_enc, aes_c_key_enc = hybrid.rsa_aes_hybrid_encryption(pickle_merchant_message_struct, self.merchant.pg_public_key, self.merchant.client_aes_key)
        MERCHANT_MESSAGE = (merchant_message_enc, aes_c_key_enc)
        PICKLE_MERCHANT_MESSAGE = pickle.dumps(MERCHANT_MESSAGE, pickle.HIGHEST_PROTOCOL)

        # PaymentGateway
        # banca salveaza cheia publica, PM a clientului si verifica PI
        UNPICKLE_MERCHANT_MESSAGE = pickle.loads(PICKLE_MERCHANT_MESSAGE)
        pg_merchant_message_enc, pg_aes_c_key_enc = UNPICKLE_MERCHANT_MESSAGE
        pg_merchant_message_dec = hybrid.rsa_aes_hybrid_decryption(pg_merchant_message_enc, self.payment_gateway._private_key, pg_aes_c_key_enc)
        pg_PM_pickled, pg_pickle_sigM_structure = pickle.loads(pg_merchant_message_dec)

        self.payment_gateway.client_aes_key = hybrid.rsa_decryption(pg_aes_c_key_enc, self.payment_gateway._private_key)
        
        pg_PM = pickle.loads(pg_PM_pickled)
        pg_client_PM_enc, pg_aes_pg_key_enc = pg_PM
        pg_client_PM_dec = hybrid.rsa_aes_hybrid_decryption(pg_client_PM_enc, self.payment_gateway._private_key, pg_aes_pg_key_enc)
        pg_pickle_PI, pg_SigC_pickle_PI = pickle.loads(pg_client_PM_dec)

        # banca verifica semnatura pentru PI
        if hybrid.signature(pg_pickle_PI).hexdigest() != pg_SigC_pickle_PI:
            raise Exception("Step4 failed. SigC mismatch!")
        else:
            print("Step4: SigC matched")

        pg_PI = pickle.loads(pg_pickle_PI)
        CardN, CardExp, CCode, Sid, Amount, PubKC, NC, M = pg_PI

        self.payment_gateway.Sid = Sid
        self.payment_gateway.Amount = Amount
        self.payment_gateway.NC = NC

        pg_M_structure = (Sid, PubKC, Amount)
        pg_pickle_sigM = pickle.dumps(pg_M_structure, pickle.HIGHEST_PROTOCOL)
        if hybrid.signature(pg_pickle_sigM).hexdigest() != pg_pickle_sigM_structure:
            raise Exception("Step4 failed. PM mismatch!")
        else:
            print("Step4: PM matched")

        # banca verifica PI
        if self.payment_gateway.is_client_payment_info_ok(pg_PI):
            self.payment_gateway.response = "FairExchange"
            print("Step4: PI matched!")
        else:
            self.payment_gateway.response = "NotFairExchange"

    def step5(self):
        # PaymentGateway
        # banca trimite (Resp, Sid, sigPG(Resp, Sid, Amount, NC)) catre merchant
        Resp = self.payment_gateway.response
        Sid = self.payment_gateway.Sid
        Amount = self.payment_gateway.Amount
        NC = self.payment_gateway.NC

        sigPG_structure = (Resp, Sid, Amount, NC)
        pickle_sigPG_structure = pickle.dumps(sigPG_structure, pickle.HIGHEST_PROTOCOL)
        sigPG =hybrid.signature(pickle_sigPG_structure).hexdigest()

        pg_message_structure = (Resp, Sid, sigPG)
        pickle_pg_message_structure = pickle.dumps(pg_message_structure, pickle.HIGHEST_PROTOCOL)
        pg_message_enc, aes_c_key_enc = hybrid.rsa_aes_hybrid_encryption(pickle_pg_message_structure, self.payment_gateway.m_public_key, self.payment_gateway.client_aes_key)
        PAYMENT_GATEWAY_MESSAGE = (pg_message_enc, aes_c_key_enc)
        PICKLE_PAYMENT_GATEWAY_MESSAGE = pickle.dumps(PAYMENT_GATEWAY_MESSAGE, pickle.HIGHEST_PROTOCOL)

        # Merchant
        UNPICKLE_PAYMENT_GATEWAY_MESSAGE = pickle.loads(PICKLE_PAYMENT_GATEWAY_MESSAGE)
        m_pg_message_enc, m_aes_c_key_enc = UNPICKLE_PAYMENT_GATEWAY_MESSAGE
        m_pg_message_dec = hybrid.rsa_aes_hybrid_decryption(m_pg_message_enc, self.merchant._private_key, m_aes_c_key_enc)
        
        m_client_public_key = self.merchant.client_public_key
        merchant_message_enc, aes_m_key_enc = hybrid.rsa_aes_hybrid_encryption(m_pg_message_dec, m_client_public_key, self.merchant.client_aes_key)
        self.merchant.client_merchant_message_enc, self.merchant.client_aes_m_key_enc = merchant_message_enc, aes_m_key_enc

    def step6(self):
        # Merchant
        MERCHANT_MESSAGE = (self.merchant.client_merchant_message_enc, self.merchant.client_aes_m_key_enc)
        PICKLE_MERCHANT_MESSAGE = pickle.dumps(MERCHANT_MESSAGE, pickle.HIGHEST_PROTOCOL)

        # Client
        # clientul primeste (Resp, Sid, sigPG(Resp, Sid, Amount, NC)) si verifica sigPG
        UNPICKLE_MERCHANT_MESSAGE = pickle.loads(PICKLE_MERCHANT_MESSAGE)
        c_merchant_message_enc, c_aes_m_key_enc = UNPICKLE_MERCHANT_MESSAGE
        c_merchant_message_dec = hybrid.rsa_aes_hybrid_decryption(c_merchant_message_enc, self.client._private_key, c_aes_m_key_enc)
        c_merchant_message_dec_unpickle = pickle.loads(c_merchant_message_dec)

        pg_response, Sid, sigPG = c_merchant_message_dec_unpickle

        c_sigPG_structure = (pg_response, Sid, self.client.Amount, self.client.NC)

        pickle_sigPG_structure = pickle.dumps(c_sigPG_structure, pickle.HIGHEST_PROTOCOL)
        if hybrid.signature(pickle_sigPG_structure).hexdigest() != sigPG:
            raise Exception("Step6 failed. SigPG mismatch!")
        else:
            print("Step6: sigPG matched")

        print("[PaymentGateway]: {}".format(pg_response))

class Client:

    def __init__(self):
        self.public_key = None
        self._private_key = None
        self._aes_key = None

    def set_aes_key(self):
        self._aes_key = hybrid.generate_aes_key()

    def set_rsa_keys(self):
        self._private_key, self.public_key = hybrid.generate_rsa_keys()

    def generate_nonce(self):
        self._nonce = hybrid.generate_random_int(6)


class Merchant:

    def __init__(self):
        self.public_key = None
        self._private_key = None
        self._aes_key = None
        self.session_id = None
        self.id = '1234'
        self.products = None

    def set_aes_key(self):
        self._aes_key = hybrid.generate_aes_key()

    def set_rsa_keys(self):
        self._private_key, self.public_key = hybrid.generate_rsa_keys()

    def generate_session_id(self):
        self.session_id = hybrid.generate_random_int(length=6)

    def load_products(self, csv_name):
        cvs_file_path = os.path.join(os.path.dirname(__file__), csv_name)
        with open(cvs_file_path, newline='') as csvfile:
            reader = csv.reader(csvfile)
            self.products = list(reader)[1:]

    def list_products(self):
        for product in self.products:
            print('Produs: {} | Pret: {} | Amount: {}'.format(product[0], product[1], product[2]))

    def is_order_ok(self, order):
        OrderDesc, Amount = order[0], order[2]

        for product in self.products:
            if OrderDesc in product:
                if Amount <= product[2]:
                    return True
        
        return False


class PaymentGateway:

    def __init__(self):
        self.public_key = None
        self._private_key = None
        self._aes_key = None
        self._bank_database = None

    def set_aes_key(self):
        self._aes_key = hybrid.generate_aes_key()

    def set_rsa_keys(self):
        self._private_key, self.public_key = hybrid.generate_rsa_keys()

    def generate_challenge_code(self):
        self.challenge_code = hybrid.generate_random_int(length=4)

    def load_bank_database(self, csv_name):
        cvs_file_path = os.path.join(os.path.dirname(__file__), csv_name)
        with open(cvs_file_path, newline='') as csvfile:
            reader = csv.reader(csvfile)
            self._bank_database = list(reader)[1:]

    def is_client_payment_info_ok(self, PI):
        CardN, CardExp, CCode, Sid, Amount, PubKC, NC, M = PI

        client_found = False
        for client_info in self._bank_database:
            if [CardN, CardExp] == client_info[:2]:
                client_found = True
                break

        if client_found is False:
            print("[PaymentGateway]: Incorrect client card info")
            return False

        if CCode != self.challenge_code:
            print("[PaymentGateway]: Incorrect Challenge Code")
            return False

        return True


if __name__ == '__main__':
    payment_gateway = PaymentGateway()
    payment_gateway.set_rsa_keys()
    payment_gateway.load_bank_database('bank.csv')

    merchant = Merchant()
    merchant.set_rsa_keys()
    merchant.load_products('merchant.csv')

    client = Client()
    client.set_rsa_keys()

    # PublicKey exchanges
    client.merchant_public_key = merchant.public_key
    client.pg_public_key = payment_gateway.public_key
    merchant.pg_public_key = payment_gateway.public_key
    payment_gateway.m_public_key = merchant.public_key

    # SubProtocols
    SetupSubProtocol(client, merchant).start()
    ExchangeSubProtocol(client, merchant, payment_gateway).start()
