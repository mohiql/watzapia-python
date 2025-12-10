import pandas as pd

def read_numbers(filepath):
    df = pd.read_excel(filepath)

    # ambil kolom yang mengandung nomor
    possible_columns = ["nomor", "number", "phone", "no", "whatsapp"]

    column_name = None
    for col in df.columns:
        if col.lower() in possible_columns:
            column_name = col
            break

    if not column_name:
        return []

    numbers = []

    for num in df[column_name]:
        num = str(num).strip().replace(".0", "")

        # jika nomor berupa angka float
        if num.endswith(".0"):
            num = num.replace(".0", "")

        # jika nomor dimulai 0 → ubah ke 62
        if num.startswith("0"):
            num = "62" + num[1:]

        numbers.append(num)

    return numbers
