import os
import subprocess


def main():
    f = open('images.qrc', 'w+')
    images = os.listdir('./img')
    f.write(u'<!DOCTYPE RCC>\n<RCC version="1.0">\n<qresource>\n')

    for item in images:
        f.write(u'<file alias="images/' + item + '">images/' + item + '</file>\n')

    f.write(u'</qresource>\n</RCC>')
    f.close()

    pipe = subprocess.Popen(r'pyrcc5 -o images.py images.qrc', stdout=subprocess.PIPE, stdin=subprocess.PIPE,
                            stderr=subprocess.PIPE, creationflags=0x08)


if __name__ == '__main__':
    main()
