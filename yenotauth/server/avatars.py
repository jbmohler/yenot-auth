import io
import PIL.Image
import PIL.ImageDraw
import PIL.ImageFont

COLORS = [
    ("gray", "black"),
    ("green", "white"),
    ("red", "black"),
    ("#F96167", "#FCE77D"),
    ("blue", "white"),
]


def construct_avatar(initials, bgcolor, fgcolor):
    n = PIL.Image.new("RGB", (32, 32), bgcolor)
    draw = PIL.ImageDraw.Draw(n)

    font = PIL.ImageFont.truetype(
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 14
    )
    mybox = font.getbbox(initials)

    width = mybox[2] - mybox[0]
    height = mybox[3] - mybox[1]
    draw.text(
        (32 // 2 - width // 2, 32 // 2 - height // 2), initials, fill=fgcolor, font=font
    )

    buf = io.BytesIO()
    n.save(buf, format="png")

    return buf.getvalue()
