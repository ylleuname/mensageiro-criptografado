import tkinter as tk
from tkinter import messagebox
import pika
from criptografia import encrypt_AES, encrypt_DES, encrypt_RSA, generate_RSA_keys
from config import AES_KEY, DES_KEY, RABBITMQ_HOST, RABBITMQ_QUEUE, PRIVATE_KEY_PATH

class ProducerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Produtor - Enviar Mensagem Criptografada")
        self.algorithm = tk.StringVar(value="AES")
        
        tk.Label(root, text="Digite o texto:").pack()
        self.text_entry = tk.Entry(root, width=50)
        self.text_entry.pack()

        tk.Label(root, text="Escolha o algoritmo:").pack()
        for alg in ["AES", "DES", "RSA"]:
            tk.Radiobutton(root, text=alg, variable=self.algorithm, value=alg).pack(anchor="w")

        tk.Button(root, text="Enviar Mensagem", command=self.send_message).pack(pady=10)
        self.encrypted_label = tk.Label(root, text="Mensagem criptografada: ")
        self.encrypted_label.pack()

    def send_message(self):
        message = self.text_entry.get()
        algoritmo = self.algorithm.get()

        if not message:
            messagebox.showwarning("Aviso", "Digite uma mensagem.")
            return

        if algoritmo == 'AES':
            encrypted = encrypt_AES(message, AES_KEY)
        elif algoritmo == 'DES':
            encrypted = encrypt_DES(message, DES_KEY)
        elif algoritmo == 'RSA':
            public_key, private_key = generate_RSA_keys()
            encrypted = encrypt_RSA(message, public_key)
            with open(PRIVATE_KEY_PATH, "wb") as f:
                f.write(private_key)
        else:
            messagebox.showerror("Erro", "Algoritmo inválido.")
            return

        self.encrypted_label.config(text=f"Criptografado: {encrypted}")

        connection = pika.BlockingConnection(pika.ConnectionParameters(RABBITMQ_HOST))
        channel = connection.channel()
        channel.queue_declare(queue=RABBITMQ_QUEUE)
        channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE, body=f"{algoritmo}|{encrypted}")
        connection.close()

        messagebox.showinfo("Sucesso", "Mensagem enviada com sucesso!")

if __name__ == "__main__":
    root = tk.Tk()
    app = ProducerApp(root)
    root.mainloop()
