import qrcode
from PIL import Image

# Ganti dengan URL repositori GitHub Anda
repo_url = "https://github.com/Okwe123/Skripsi"  

qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)
qr.add_data(repo_url)
qr.make(fit=True)

img = qr.make_image(fill_color="black", back_color="white")
img.save("github_qr.png")

# Tampilkan di Streamlit
st.image("github_qr.png", caption="Scan untuk mengakses kode sumber")