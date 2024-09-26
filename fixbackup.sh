#!/bin/bash

# Direktori dan file yang akan dihapus
CONF_FILE="/root/.config/rclone/rclone.conf"

# Cek apakah file lama ada dan hapus jika ada
if [ -f "$CONF_FILE" ]; then
    echo "Menghapus file lama: $CONF_FILE"
    rm -f "$CONF_FILE"
else
    echo "File lama tidak ditemukan: $CONF_FILE"
fi

# Unduh file baru menggunakan wget
echo "Mengunduh file baru..."
wget -O "$CONF_FILE" "https://github.com/githubkuanyar/vip/raw/main/limit/rclone.conf" >/dev/null 2>&1

# Cek apakah unduhan berhasil
if [ $? -eq 0 ]; then
    echo "Unduhan berhasil, file baru telah tersimpan di $CONF_FILE"
else
    echo "Gagal mengunduh file baru."
fi
