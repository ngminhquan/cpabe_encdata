from PIL import Image
import io

def image_to_byte_array(image_path):
    with open(image_path, "rb") as img_file:
        return img_file.read()

# Đường dẫn đến hình ảnh
image_path = "pattern.png"

# Chuyển đổi hình ảnh sang byte array
byte_array = image_to_byte_array(image_path)

def byte_array_to_image(byte_array):
    return Image.open(io.BytesIO(byte_array))

# Chuyển đổi byte array thành hình ảnh
image = byte_array_to_image(byte_array)

# Hiển thị hình ảnh (cần thêm code tương ứng để hiển thị)
image.show()

