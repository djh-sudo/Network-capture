import sys
import whois


def analysis_dns(name):
    try:
        res = whois.whois(name)
    except Exception as e:
        with open('log', 'a+') as f:
            sys.stdout = f
            print(e)
            f.close()
            sys.stdout = sys.__stdout__
        return []
    return res
