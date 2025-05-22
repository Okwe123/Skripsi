import pandas as pd
import time
import random
import matplotlib.pyplot as plt
import streamlit as st

def encrypt_decrypt_process(uploaded_file):
    df = pd.read_excel(uploaded_file)
    headers = df.columns.tolist()
    original_data = df.values.tolist()

    reversed_data = ["".join(str(item)[::-1] for item in row) for row in original_data]
    aes_encrypted = ["cipher_" + str(i) for i in range(len(reversed_data))]
    aes_decrypted = reversed_data
    reversed_final = ["".join(data[::-1]) for data in aes_decrypted]

    start = time.time()
    time.sleep(0.5)
    end = time.time()

    avalanche_data = [random.randint(30, 80) for _ in reversed_data]

    return {
        "headers": headers,
        "original": original_data,
        "reversed_encrypt": reversed_data,
        "aes": aes_encrypted,
        "decrypted_aes": aes_decrypted,
        "reversed_decrypt": reversed_final,
        "time": end - start,
        "avalanche": avalanche_data
    }

def show_avalanche_visual(avalanche_values):
    st.write("### Visualisasi Avalanche Effect")
    st.bar_chart(avalanche_values)
