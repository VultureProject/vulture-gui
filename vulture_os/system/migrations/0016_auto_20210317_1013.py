# Generated by Django 3.0.5 on 2021-03-17 10:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('system', '0015_auto_20210305_1048'),
    ]

    operations = [
        migrations.AlterField(
            model_name='errortemplate',
            name='error_400_html',
            field=models.TextField(default='HTTP/1.1 400 Bad Request\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\n<html><body><h1>400 Bad request</h1>\n<p>Your browser sent an invalid request.</p>\n</body></html>', help_text='HTML code to render if 400 (Bad Request) code is returned.'),
        ),
        migrations.AlterField(
            model_name='errortemplate',
            name='error_403_html',
            field=models.TextField(default="HTTP/1.1 403 Forbidden\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\n<html><body><h1>403 Forbidden</h1>\n<p>You don't have permission to access this url on this server.<br/></p>\n</body></html>", help_text='HTML code to render if 403 (Forbidden) code is returned.'),
        ),
        migrations.AlterField(
            model_name='errortemplate',
            name='error_405_html',
            field=models.TextField(default='HTTP/1.1 405 Method Not Allowed\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\n<html><body><h1>405 Method Not Allowed</h1>\n<p>The requested method is not allowed for that URL.</p>\n</body></html>', help_text='HTML code to render if 405 (Method Not Allowed) code is returned.'),
        ),
        migrations.AlterField(
            model_name='errortemplate',
            name='error_408_html',
            field=models.TextField(default='HTTP/1.1 408 Request Timeout\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\n<html><body><h1>408 Request Timeout</h1>\n<p>Server timeout waiting for the HTTP request from the client.</p>\n</body></html>', help_text='HTML code to render if 408 (Request Timeout) code is returned.'),
        ),
        migrations.AlterField(
            model_name='errortemplate',
            name='error_425_html',
            field=models.TextField(default='HTTP/1.1 425 Too Early\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\n<html><body><h1>425 Too Early</h1>\n<p>.</p>\n</body></html>', help_text='HTML code to render if 425 (Too Early) code is returned.'),
        ),
        migrations.AlterField(
            model_name='errortemplate',
            name='error_429_html',
            field=models.TextField(default='HTTP/1.1 429 Too Many Requests\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\n<html><body><h1>429 Too Many Requests</h1>\n<p>The user has sent too many requests in a given amount of time.</p>\n</body></html>', help_text='HTML code to render if 429 (Too Many Requests) code is returned.'),
        ),
        migrations.AlterField(
            model_name='errortemplate',
            name='error_500_html',
            field=models.TextField(default='HTTP/1.1 500 Internal Server Error\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\n<html><body><h1>500 Internal Server Error</h1>\n<p>The server encountered an internal error or\nmisconfiguration and was unable to complete\nyour request.</p>\n<p>Please contact the server administrator\nto inform them of the time this error occurred,\nand the actions you performed just before this error.</p>\n<p>More information about this error may be available\nin the server error log.</p>\n</body></html>', help_text='HTML code to render if 500 (Internal Server Error) code is returned.'),
        ),
        migrations.AlterField(
            model_name='errortemplate',
            name='error_502_html',
            field=models.TextField(default='HTTP/1.1 502 Bad Gateway\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\n<html><body><h1>502 Bad Gateway</h1>\n<p>The proxy server received an invalid response from an upstream server.<br/></p>\n</body></html>', help_text='HTML code to render if 502 (Bad Gateway) code is returned.'),
        ),
        migrations.AlterField(
            model_name='errortemplate',
            name='error_503_html',
            field=models.TextField(default='HTTP/1.1 503 Service Unavailable\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\n<html><body><h1>503 Service Unavailable</h1>\n<p>The server is temporarily unable to service your\nrequest due to maintenance downtime or capacity\nproblems. Please try again later.</p>\n</body></html>', help_text='HTML code to render if 503 (Service Unavailable) code is returned.'),
        ),
        migrations.AlterField(
            model_name='errortemplate',
            name='error_504_html',
            field=models.TextField(default='HTTP/1.1 504 Gateway Timeout\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\n<html><body><h1>504 Gateway Timeout</h1>\n<p>The gateway did not receive a timely response\nfrom the upstream server or application.</p>\n</body></html>', help_text='HTML code to render if 504 (Gateway Timeout) code is returned.'),
        ),
    ]
