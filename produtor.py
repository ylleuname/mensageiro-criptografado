import tkinter as tk
from tkinter import messagebox
import pika
from criptografia import (
    encrypt_AES, encrypt_DES, encrypt_RSA,
    generate_RSA_keys as generate_encryption_keys, 
    generate_persistent_signing_keys,
    sign_message_RSA
)
from config import AES_KEY, DES_KEY, RABBITMQ_HOST, RABBITMQ_QUEUE, PRIVATE_KEY_PATH

PRODUCER_NAME = "Manu"
SIGNING_PRIVATE_KEY_PATH = 'producer_signing_private.pem'
SIGNING_PUBLIC_KEY_PATH = 'producer_signing_public.pem'

class ProducerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Produtor - Criptografar e Assinar")
        
        self.signing_private_key = None
        self.signing_public_key_pem_str = None

        try:
            with open(SIGNING_PRIVATE_KEY_PATH, "rb") as f:
                self.signing_private_key = f.read() # Bytes
            with open(SIGNING_PUBLIC_KEY_PATH, "rb") as f:
                self.signing_public_key_pem_str = f.read().decode() # String
        except FileNotFoundError:
            try:
                public_key_bytes, private_key_bytes = generate_persistent_signing_keys()
                self.signing_private_key = private_key_bytes
                self.signing_public_key_pem_str = public_key_bytes.decode()
                messagebox.showinfo("Chaves de Assinatura", "Novas chaves de assinatura foram geradas e salvas.")
            except Exception as e:
                messagebox.showerror("Erro Crítico", f"Falha ao gerar chaves de assinatura: {e}")
                if self.root.winfo_exists(): self.root.destroy()
                return
        except Exception as e:
            messagebox.showerror("Erro Crítico", f"Falha ao carregar chaves de assinatura: {e}")
            if self.root.winfo_exists(): self.root.destroy()
            return
        
        if not self.root.winfo_exists(): return

        self.algorithm_var = tk.StringVar(value="AES")
        
        tk.Label(self.root, text="Mensagem:").pack()
        self.message_entry = tk.Entry(self.root, width=50)
        self.message_entry.pack()

        tk.Label(self.root, text="Algoritmo de Criptografia:").pack()
        for alg in ["AES", "DES", "RSA"]:
            tk.Radiobutton(self.root, text=alg, variable=self.algorithm_var, value=alg).pack(anchor="w")

        tk.Button(self.root, text="Enviar Mensagem Assinada", command=self.process_and_send).pack(pady=10)
        self.info_label = tk.Label(self.root, text="Status: Pronto")
        self.info_label.pack()

    def process_and_send(self):
        if not self.signing_private_key:
            messagebox.showerror("Erro", "Chave de assinatura não disponível.")
            return

        original_message = self.message_entry.get()
        encryption_algorithm = self.algorithm_var.get()

        if not original_message:
            messagebox.showwarning("Atenção", "Por favor, digite uma mensagem.")
            return

        encrypted_content = ""
        if encryption_algorithm == 'AES':
            encrypted_content = encrypt_AES(original_message, AES_KEY)
        elif encryption_algorithm == 'DES':
            encrypted_content = encrypt_DES(original_message, DES_KEY)
        elif encryption_algorithm == 'RSA':
            enc_pub_key, enc_priv_key = generate_encryption_keys()
            encrypted_content = encrypt_RSA(original_message, enc_pub_key)
            with open(PRIVATE_KEY_PATH, "wb") as f:
                f.write(enc_priv_key)
        else:
            messagebox.showerror("Erro", "Algoritmo de criptografia não selecionado ou inválido.")
            return

        self.info_label.config(text=f"Criptografado: {encrypted_content[:30]}...")

        data_to_sign_str = f"{encryption_algorithm}|{PRODUCER_NAME}|{encrypted_content}"
        signature = sign_message_RSA(data_to_sign_str, self.signing_private_key)

        message_to_send = f"{encryption_algorithm}|{PRODUCER_NAME}|{encrypted_content}|{signature}|{self.signing_public_key_pem_str}"

        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(RABBITMQ_HOST))
            channel = connection.channel()
            channel.queue_declare(queue=RABBITMQ_QUEUE)
            channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE, body=message_to_send)
            connection.close()
            messagebox.showinfo("Sucesso", "Mensagem criptografada e assinada foi enviada!")
            self.info_label.config(text="Status: Mensagem enviada.")
        except Exception as e:
            messagebox.showerror("Erro RabbitMQ", f"Não foi possível enviar a mensagem: {e}")
            self.info_label.config(text="Status: Falha no envio.")

if __name__ == "__main__":
    gui_root = tk.Tk()
    app_instance = ProducerApp(gui_root)
    if gui_root.winfo_exists():
        gui_root.mainloop()