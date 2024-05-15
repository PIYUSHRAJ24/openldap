import base64

pdf_sample = """
THIS IS A SAMPLE PDF DOCUMENT

Languages:
- Hindi: भारत (Bhārat)
- Bengali: ভারত (Bharat)
- Telugu: భారతదేశం (Bhāratadēśam)
- Marathi: भारत (Bhārat)
- Tamil: இந்தியா (Intiyā)
- Urdu: بھارت (Bharat)
- Gujarati: ભારત (Bhārat)
- Kannada: ಭಾರತ (Bhārata)
- Odia: ଭାରତ (Bhārata)
- Malayalam: ഇന്ത്യ (Indya)
- Spanish: India
- French: Inde
- German: Indien
- Italian: India
- Portuguese: Índia
- Dutch: India
- Russian: Индия (Indiya)
- Chinese (Simplified): 印度 (Yìndù)
- Japanese: インド (Indo)
- Korean: 인도 (Indo)
- Arabic: الهند (Al-Hind)
- Turkish: Hindistan
- Vietnamese: Ấn Độ
- Thai: อินเดีย (In-dii-a)
- Greek: Ινδία (Indía)
- Swedish: Indien
- Danish: Indien
- Norwegian: India
- Finnish: Intia
- Polish: Indie
- Hungarian: India
- Czech: Indie
- Romanian: India
- Ukrainian: Індія (Indiya)
- Bulgarian: Индия (Indiya)
- Serbian: Индија (Indija)
- Croatian: Indija
- Slovenian: Indija
- Lithuanian: Indija
- Latvian: Indija
- Estonian: India
- Icelandic: Indland

CONFIDENTIALITY NOTICE

This PDF Document is for Demonstration and Educational Purposes Only.
It is intended to showcase the capabilities of our PDF generation system and demonstrate the layout of different used cases.
It should not be considered as a legally binding or official document.
Please refrain from using this document for any official, legal, or production purposes.
"""

sample_pdfB64 = base64.b64encode((pdf_sample*25).encode()).decode()

xml_sample = """
<Root>
    <Data>Sample XML Data</Data>
    <Description>
        CONFIDENTIALITY NOTICE
        This XML Document is for Demonstration and Educational Purposes Only.
        It is intended to showcase the capabilities of our XML generation system and demonstrate the layout of different used cases.
        It should not be considered as a legally binding or official document.
        Please refrain from using this document for any official, legal, or production purposes.
    </Description>
    <Certificate>
        <Requester>DEMO</Requester>
    </Certificate>
</Root>
"""

sample_xmlB64 = base64.b64encode((xml_sample*25).encode()).decode()
