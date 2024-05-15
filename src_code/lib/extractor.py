from pdf2image import convert_from_bytes
import pytesseract

class Extractor:
    def __init__(self):
        self.active = True

    def extract_pdf(self, data: bytes):
        """
        Extracts text from supplied pdf bytes

        Args:
            data (bytes): opened pdf file
        """

        # Convert the pdf to images
        pages = convert_from_bytes(data)

        # # Iterate over each image
        # for i, page in enumerate(pages):
        #     page.save('page-%d.png' % i, 'PNG')

        text = ''
        # Iterate over each image
        for page in pages:
            text += pytesseract.image_to_string(page, lang='eng')+'\n'
        return text.replace("  ","")
