from mailjet_rest import Client

api_key = '27b590b8f1a01b0ab9f3dff6ac16536f'
api_secret = '2047a7fca67037c53bd01ce49af798a0'

mailjet = Client(auth=(api_key, api_secret), version='v3.1')

data = {
  'Messages': [
    {
      "From": {
        "Email": "noreply@domainkamu.com",
        "Name": "E-Perpus SMAN 1 Tinombo"
      },
      "To": [
        {
          "Email": "emailtujuan@gmail.com",
          "Name": "Faldy"
        }
      ],
      "Subject": "Tes Kirim Email via Mailjet REST API",
      "TextPart": "Halo Faldy, ini pengujian dari Mailjet API.",
      "HTMLPart": "<h3>Halo Faldy!</h3><p>Ini pengujian dari <b>Mailjet REST API</b>.</p>"
    }
  ]
}

result = mailjet.send.create(data=data)
print(result.status_code)
print(result.json())
