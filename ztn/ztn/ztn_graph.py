import graphistry
import pandasticsearch

class ZTN_Graph():
    def __init__(self, url, user, password):
        self.url = url
        self.user = user
        self.password = password

        ## or via fresh short-lived token below that expires in 1:00:00 after initial generation
        # graphistry.register(api=3, protocol="https", server="hub.graphistry.com", token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Im5hdHpiZXJnIiwiaWF0IjoxNjQ2MDc5ODcyLCJleHAiOjE2NDYwODM0NzIsImp0aSI6IjA3MzZlYTA5LWE1MDMtNDYzNy04NDgwLTI5NjRlMzRkODUxZiIsInVzZXJfaWQiOjYzMzEsIm9yaWdfaWF0IjoxNjQ2MDc5ODcyfQ.7GvRglH37_FYWJ73lQ-vTCIRp0X4acY6kzVtll2Bnqk")

    def login(self):
       graphistry.register(api=3, username=self.user, password=self.password)