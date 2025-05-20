import tkinter as tk
import threading
import pika
from criptografia import decrypt_AES, decrypt_DES, decrypt_RSA
from config import AES_KEY, DES_KEY, PRIVATE_KEY_PATH, RABBITMQ_HOST, RABBITMQ_QUEUE

class ConsumerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Consumidor - Receber Mensagem")
        
        tk.Button(root, text="Iniciar Escuta", command=self.start_listening).pack(pady=10)

        self.encrypted_label = tk.Label(root, text="Mensagem criptografada: ")
        self.encrypted_label.pack()
        self.decrypted_label = tk.Label(root, text="Mensagem decifrada: ")
        self.decrypted_label.pack()

    def callback(self, ch, method, properties, body):
        data = body.decode()
        algoritmo, encrypted = data.split('|', 1)

        if algoritmo == 'AES':
            decrypted = decrypt_AES(encrypted, AES_KEY)
        elif algoritmo == 'DES':
            decrypted = decrypt_DES(encrypted, DES_KEY)
        elif algoritmo == 'RSA':
            with open(PRIVATE_KEY_PATH, "rb") as f:
                private_key = f.read()
            decrypted = decrypt_RSA(encrypted, private_key)
        else:
            decrypted = "Algoritmo desconhecido."

        self.encrypted_label.config(text=f"Criptografado: {encrypted}")
        self.decrypted_label.config(text=f"Decifrado: {decrypted}")

    def start_listening(self):
        thread = threading.Thread(target=self.consume)
        thread.daemon = True
        thread.start()

    def consume(self):
        connection = pika.BlockingConnection(pika.ConnectionParameters(RABBITMQ_HOST))
        channel = connection.channel()
        channel.queue_declare(queue=RABBITMQ_QUEUE)
        channel.basic_consume(queue=RABBITMQ_QUEUE, on_message_callback=self.callback, auto_ack=True)
        channel.start_consuming()

if __name__ == "__main__":
    root = tk.Tk()
    app = ConsumerApp(root)
    root.mainloop()
