import tldextract
import re
from urllib.parse import urlparse,parse_qs
import labels

def get_tld(url):
    ext = tldextract.extract(url).suffix
    return ext

# url = "https://www.example.com"
# tld = get_tld(url)
# print(f'TLD: {tld}')


def build_url(url:str):

    SUSPICIOUS_KEYWORDS = list(set([
    'login', 'signin', 'logout', 'auth', 'authenticate', 'passwd', 'password',
    'credentials', 'verify', 'validation', 'session', 'account', 'bank', 'securebank',
    'ebanking', 'invoice', 'payment', 'billing', 'transfer', 'transaction', 'creditcard',
    'debit', 'paypal', 'money', 'wallet', 'deposit', 'atm', 'webmail', 'email', 'mailbox',
    'outlook', 'office365', 'exchange', 'inbox', 'smtp', 'imap', 'secure', 'security',
    'suspend', 'disabled', 'risk', 'alert', 'breach', 'urgent', 'warning', 'locked',
    'verify-now', 'immediately', 'attention', 'support', 'helpdesk', 'update',
    'maintenance', 'itdesk', 'service', 'admin', 'administrator', 'sysadmin', 'staff',
    'win', 'free', 'bonus', 'gift', 'reward', 'claim', 'prize', 'offer', 'promo',
    'deal', 'trial', 'giveaway', 'discount', 'voucher', 'apple', 'google', 'facebook',
    'amazon', 'netflix', 'paypal', 'microsoft', 'outlook', 'dropbox', 'dhl', 'fedex',
    'irs', 'gov', 'ups'
    ]))

    if not url.startswith(('http://', 'https://')):
        hturl = 'http://' + url
    else:
        hturl = url
    tags = []
    tags.append(1) if 'login' in url.lower() else tags.append(0)
    tags.append(1) if 'client' in url.lower() else tags.append(0)
    tags.append(1) if 'server' in url.lower() else tags.append(0)
    tags.append(1) if 'admin' in url.lower() else tags.append(0)
    tags.append(1) if bool(re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url))  else tags.append(0)
    tags.append(1) if bool(re.search(r'\b(?:bit\.ly|t\.co|goo\.gl|tinyurl\.com|ow\.ly|buff\.ly|is\.gd|j\.mp|tr\.im|dlvr\.it)\b', url, re.IGNORECASE)) else tags.append(0)
    tags.append(len(url))
    tags.append(url.count('.'))
    tags.append(url.count('https'))
    tags.append(url.count('http'))
    tags.append(url.count('%'))
    tags.append(url.count('-'))
    tags.append(url.count('www'))
    tags.append(url.count('@'))
    tags.append(url.count('#'))
    tags.append(url.count(';'))
    tags.append(url.count('_'))
    tags.append(url.count("?"))
    tags.append(url.count('='))
    tags.append(url.count('&'))
    tags.append(sum(1 for char in url if char.isalpha()))
    tags.append(sum(1 for char in url if char.isdigit()))
    tags.append(len(urlparse(hturl).path)-1)
    tags.append(url.count('/'))
    tags.append(urlparse(hturl).path.count('0'))
    tags.append(urlparse(hturl).path.count('%'))
    tags.append(len(re.findall(r'[a-z]', url.split('?')[0].split('#')[0])))
    tags.append(len(re.findall(r'[A-Z]', url.split('?')[0].split('#')[0])))
    tags.append(1 if any(len(dir) == 1 for dir in url.strip('/').split('/')) else 0)
    tags.append(int(any(dir.isupper() for dir in urlparse(url).path.strip('/').split('/'))))
    tags.append(len(urlparse(url).query))
    tags.append(len(parse_qs(urlparse(url).query)))
    tags.append(len(urlparse(url).netloc))
    tags.append((urlparse(url).netloc).count('-'))
    tags.append((urlparse(url).netloc).count('@'))
    tags.append(sum(1 for char in (urlparse(url).netloc) if not char.isalnum()))
    tags.append(sum(1 for char in (urlparse(url).netloc) if char.isdigit()))
    tags.append(len(get_tld(url)))
    tags.append(labels.getlabel(get_tld(url)))


    return tags



columns = [
    'url_has_login', 'url_has_client', 'url_has_server', 
    'url_has_admin', 'url_has_ip', 'url_isshorted', 'url_len', 'url_count_dot', 
    'url_count_https', 'url_count_http', 'url_count_perc', 'url_count_hyphen', 
    'url_count_www', 'url_count_atrate', 'url_count_hash', 'url_count_semicolon', 
    'url_count_underscore', 'url_count_ques', 'url_count_equal', 'url_count_amp', 
    'url_count_letter', 'url_count_digit',  
    'path_len', 
    'path_count_no_of_dir', 'path_count_zero', 
    'path_count_pertwent',  'path_count_lower', 
    'path_count_upper',  'path_has_singlechardir', 
    'path_has_upperdir', 'query_len', 'query_count_components', 'pdomain_len', 
    'pdomain_count_hyphen', 'pdomain_count_atrate', 'pdomain_count_non_alphanum', 
    'pdomain_count_digit', 'tld_len', 'tld',  
    
]
