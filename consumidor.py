import tkinter as tk
from tkinter import messagebox
import threading
import pika

from criptografia import decrypt_AES, decrypt_DES, decrypt_RSA, verify_message_signature_RSA
from config import AES_KEY, DES_KEY, PRIVATE_KEY_PATH, RABBITMQ_HOST, RABBITMQ_QUEUE

class ConsumerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Consumidor - Verificar e Decifrar")
        
        self.listen_button = tk.Button(self.root, text="Iniciar Escuta", command=self.start_listening_thread)
        self.listen_button.pack(pady=10)

        self.info_display = tk.Label(self.root, text="Aguardando mensagens...", justify=tk.LEFT, height=6, width=70)
        self.info_display.pack()
        self.decrypted_display = tk.Label(self.root, text="", justify=tk.LEFT, wraplength=450)
        self.decrypted_display.pack()

    def update_display(self, producer_text, signature_text, encrypted_text, decrypted_text):
        self.info_display.config(text=f"{producer_text}\n{signature_text}\n{encrypted_text}")
        self.decrypted_display.config(text=f"{decrypted_text}")

    def message_callback(self, ch, method, properties, body):
        raw_message = body.decode()
        
        p_text = "Produtor: Erro"
        s_text = "Assinatura: Erro"
        e_text = f"Criptografado: {raw_message[:50]}..."
        d_text = "Decifrado: Erro no processamento"

        try:
            enc_alg, prod_name, enc_payload, sig_b64, prod_signing_pub_key_str = raw_message.split('|', 4)
            
            e_text = f"Criptografado (pré-verificação): {enc_payload[:50]}..." # Atualiza payload antes de verificar

            data_that_was_signed = f"{enc_alg}|{prod_name}|{enc_payload}"
            is_valid_signature = verify_message_signature_RSA(data_that_was_signed, sig_b64, prod_signing_pub_key_str)

            if is_valid_signature:
                p_text = f"Produtor: {prod_name}"
                s_text = "Assinatura: Verificada ✔️"
                e_text = f"Criptografado (verificado): {enc_payload[:50]}..."
                
                dec_content = "Falha na decifragem."
                if enc_alg == 'AES':
                    dec_content = decrypt_AES(enc_payload, AES_KEY)
                elif enc_alg == 'DES':
                    dec_content = decrypt_DES(enc_payload, DES_KEY)
                elif enc_alg == 'RSA':
                    try:
                        with open(PRIVATE_KEY_PATH, "rb") as f:
                            rsa_dec_key = f.read()
                        dec_content = decrypt_RSA(enc_payload, rsa_dec_key)
                    except Exception as e_dec:
                        dec_content = f"Erro ao decifrar RSA: {e_dec}"
                else:
                    dec_content = "Algoritmo de criptografia desconhecido."
                d_text = f"Decifrado: {dec_content}"
            else:
                p_text = f"Produtor: {prod_name} (ASSINATURA INVÁLIDA)"
                s_text = "Assinatura: INVÁLIDA ❌"
                e_text = f"Criptografado (NÃO CONFIÁVEL): {enc_payload[:50]}..."
                d_text = "Decifrado: (mensagem não confiável, assinatura inválida)"
        except ValueError:
            s_text = "Assinatura: Erro de formato de mensagem"
        except Exception as e_cb:
            s_text = f"Assinatura: Erro geral ({e_cb})"
        
        self.root.after(0, self.update_display, p_text, s_text, e_text, d_text)
        ch.basic_ack(delivery_tag=method.delivery_tag)

    def start_listening_thread(self):
        self.listen_button.config(state=tk.DISABLED)
        thread = threading.Thread(target=self.run_consumer_logic, daemon=True)
        thread.start()
        messagebox.showinfo("Consumidor", "Escuta de mensagens iniciada em segundo plano.")

    def run_consumer_logic(self):
        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(RABBITMQ_HOST))
            channel = connection.channel()
            channel.queue_declare(queue=RABBITMQ_QUEUE)
            channel.basic_consume(queue=RABBITMQ_QUEUE, on_message_callback=self.message_callback, auto_ack=False)
            channel.start_consuming()
        except pika.exceptions.AMQPConnectionError as e:
            self.root.after(0, lambda: messagebox.showerror("Erro RabbitMQ", f"Consumidor: Falha na conexão - {e}"))
            self.root.after(0, lambda: self.listen_button.config(state=tk.NORMAL))
        except Exception as e_thread:
            self.root.after(0, lambda: messagebox.showerror("Erro Consumidor", f"Consumidor: Erro na thread - {e_thread}"))
            self.root.after(0, lambda: self.listen_button.config(state=tk.NORMAL))

if __name__ == "__main__":
    gui_root_consumer = tk.Tk()
    app_consumer_instance = ConsumerApp(gui_root_consumer)
    gui_root_consumer.mainloop()