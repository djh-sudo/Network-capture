import OpenSSL
from dateutil import parser


def analysis_certification(file_name):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, open(file_name, 'rb').read())
    certIssue = cert.get_issuer()
    print('version: ', cert.get_version() + 1)
    print('sequence: ', hex(cert.get_serial_number()))
    print('signature-algorithm: ', cert.get_signature_algorithm().decode("UTF-8"))
    print('Issuer: ', certIssue.commonName)
    datetime_struct = parser.parse(cert.get_notBefore().decode("UTF-8"))
    print('Validity period from ', datetime_struct.strftime('%Y-%m-%d %H:%M:%S'))
    datetime_struct = parser.parse(cert.get_notAfter().decode("UTF-8"))
    print(' to ', datetime_struct.strftime('%Y-%m-%d %H:%M:%S'))
    print('Expired: ', cert.has_expired())
    print('pubkey length: ', cert.get_pubkey().bits())
    print('public key: ', OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey()).decode("utf-8"))
    print('infomation: ')
    for item in certIssue.get_components():
        print(item[0].decode("utf-8"), "  ——  ", item[1].decode("utf-8"))

    print('extension count: ', cert.get_extension_count())


def analysis_certification_dire(byte_info):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, byte_info)
    certIssue = cert.get_issuer()
    version = 'version: ' + str(cert.get_version() + 1)
    seq = 'sequence: ' + hex(cert.get_serial_number())
    sig_algoth = 'signature-algorithm: ' + cert.get_signature_algorithm().decode("UTF-8")
    issuer = 'Issuer: ' + certIssue.commonName
    datetime_struct = parser.parse(cert.get_notBefore().decode("UTF-8"))
    time = 'Validity period from ' + datetime_struct.strftime('%Y-%m-%d %H:%M:%S')
    datetime_struct = parser.parse(cert.get_notAfter().decode("UTF-8"))
    time =time + ' to ' + datetime_struct.strftime('%Y-%m-%d %H:%M:%S')
    expired = 'Expired: ' + str(cert.has_expired())
    pub_len = 'pubkey length: ' + str(cert.get_pubkey().bits())
    pubkey = 'public key: ' + OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey()).decode("utf-8")
    info = []
    for item in certIssue.get_components():
        info.append(item[0].decode("utf-8") + "  ——  " + item[1].decode("utf-8"))
    extention_len = 'extension count: ' + str(cert.get_extension_count())
    return version, seq, sig_algoth, issuer, time, expired, pub_len, pubkey, info, extention_len
