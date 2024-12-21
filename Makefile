all:
	python3 manage.py makemigrations
	python3 manage.py migrate
	python3 manage.py runserver 8000

migrations:
	python3 manage.py makemigrations

migrate:
	python3 manage.py migrate

cleardb:
	python3 manage.py cleardb

# loadtheme:
# 	python3 manage.py loaddata init/planflux_theme.json

fakedata:
	python3 manage.py create_fake_data

superuser:
	python3 manage.py createsuperuser --noinput

addstatictoken:
	python3 manage.py addstatictoken

install:
	( \
		python3 -m venv venv; \
		source venv/bin/activate; \
		pip install -r requirements.txt; \
		pre-commit install; \
		python3 manage.py createsuperuser --noinput; \
	)

venv:
	( \
		python3 -m venv venv; \
		source venv/bin/activate; \
		pip install -r requirements.txt; \
	)

serveo:
	ssh -R planflux:80:localhost:8005 serveo.net

cgm:
	python3 manage.py cgm


unset:
	unset FIREBASE_PRIVATE_KEY DB_NAME DB_USER DB_PASSWORD DB_HOST DB_PORT AZURE_FTPS_BACKEND_USERNAME AZURE_FTPS_BACKEND_PASSWORD AZURE_FTPS_FUNCTION_APP_USERNAME AZURE_FTPS_FUNCTION_APP_PASSWORD AZURE_FTPS_SELENIUM_USERNAME AZURE_FTPS_SELENIUM_PASSWORD

test_views:
	pytest --cov-report term --cov=api
