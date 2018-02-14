from bs4 import BeautifulSoup

def get_input(text):
    soup = BeautifulSoup(text,'lxml')
    result_one= {}
    try:
        for _form in soup.find_all('form'):
            for _input in soup.find_all('input'):
                try:
                    value = _input['value'] if _input['value'] else 'no'
                except:
                    value = 'no' #代表无value属性
                try:
                    result_one[_input['name']] = value
                except:
                    pass
        if result_one:
            print('[find input]',result_one)
        return result_one
    except:
        return False



