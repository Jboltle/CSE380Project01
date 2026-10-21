import requests
import json
import os

try:
	URLclear = "http://127.0.0.1:5000/clear"
	r_clear = requests.get(url = URLclear)
	
	URL = "http://127.0.0.1:5000/create_user"
	PARAMS = {'first_name': 'James', 'last_name': 'Mariani', 'username': 'james.mariani', 'email_address': 'james@mariani.com', 'password': 'Examplepassword1', 'salt': '4ErH1inwG6dJW0cu'}

	r = requests.post(url = URL, data = PARAMS)
	data = r.json()

	PARAMS = {'first_name': 'James', 'last_name': 'Mariani', 'username': 'jmm', 'email_address': 'jmm@mariani.com', 'password': 'Examplepassword2', 'salt': 'FE8x1gO+7z0B'}

	r = requests.post(url = URL, data = PARAMS)
	data = r.json()

	URLLogin = "http://127.0.0.1:5000/login"
	LOGINPARAMS = {'username': 'jmm', 'password': 'Examplepassword1'}

	r_login = requests.post(url = URLLogin, data = LOGINPARAMS)
	login_data = r_login.json()

	solution = {"status": 2, "jwt": "NULL"}
		
	for key in solution:
		if solution[key] != login_data[key]:
			print('Test Failed')
			quit()
	print('Test Passed')
except:
	print('Test Failed')
