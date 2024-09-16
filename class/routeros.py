from librouteros import connect


class RouterOS:

    def __init__(self, host, username, password, port=8728):
        
        self.mk_host = host
        self.mk_user = username
        self.mk_pass = password
        self.mk_port = port

        self.logged = False


    def __login(self):

        try:
            self.api = connect(
                username=self.mk_user,
                password=self.mk_pass,
                host=self.mk_host,
                )
            self.logged = True

        except:
            self.logged = False

        return self.logged




    def __logout(self):

        if not (self.logged):
            return False

        try:
            self.connection.disconnect()      
            self.logged = False  
            return True
        except:
            return False


    def __source(self, resource):
        return  self.api.path(resource)










    @staticmethod
    def __isvalidCredentials(credentials) -> bool:
        return (credentials.keys() >= {'host', 'user', 'pass'})


    """
        RULE = {
            'chain':'dstnat',
            'action':'dst-nat',
            'protocol':'tcp',
            'to-addresses':'100.78.254.3',
            'to-ports':'3122',
            'dst-address':'198.0.0.1',
            'dst-port':'2000'
        }


        TEST = {
            'chain':'dstnat',
            'action':'dst-nat',
            'protocol':'tcp',
            'to-addresses':'100.78.254.3',
            'dst-address':'198.0.0.1'
        }


        similar_dict(RULE, TEST, sensitive)

    """
    def similar_dict(MASTER, SLAVE, sense=False) -> dict:

        if(len(SLAVE) > len(MASTER)):
            return False
        
        if(sense):
            # SLAVE need 50% parameter of master to continue
            if((len(MASTER)-len(SLAVE)) >= (len(MASTER)/2)):
                return False

        for __slave in SLAVE:

            __slave  = str(SLAVE[__slave])
            __master = str(MASTER[__slave])


            if(__slave != __master):
                return False

        return True










    """ 
        CREDENTIAL = {
            'host': "ip_address",
            'user': "username",
            'pass': "password",
            'port': api_port
        }


        SOURCE = "/ip/firewall/nat"

        RouterOS.getall(CREDENTIAL, "/ip/firewall/nat")
    """
    def getall(credentials, resource) -> dict:
        if not (RouterOS.__isvalidCredentials(credentials)):
            return None
            
        __out = None
        try:
            mk = RouterOS(credentials['host'], credentials['user'], credentials['pass'], credentials['port'])   
            
           
            if(mk.__login()):       
                __out = list(mk.__source(resource))

            mk.__logout()
        
        except:
            pass

        return __out








    """ 
        CREDENTIAL = {
            'host': "ip_address",
            'user': "username",
            'pass': "password",
            'port': api_port
        }


        SOURCE = "/ip/firewall/nat"

        MANDATORY = {
            'to-addresses',
            'to-ports',
            'dst-address',
            'dst-port'
        }

        Types Allowed:
            'key' dict,
            'dict' key and value

        Mikrotik.get_raw(types, CREDENTIAL, SOURCE, MANDATORY)
    """
    def get_raw(types, credentials, resource, args) -> any:
        
        if not (RouterOS.__isvalidCredentials(credentials)):
            return None

        __outarray = []
        try:

            __getall = RouterOS.getall(credentials, resource)
            for __item in __getall:

                item = {}
                item['host'] = credentials['host']
                item.update(__item)
                # item = item + __item

                
                if(types == 'key'):
                    if(item.keys() >= args):
                        __outarray.append(item)

                if(types == 'dict'):

                    __exists = False
                    for __less in args:
                        if(__less in item):
                            if(str(item[__less]) == str(args[__less])):
                                __exists = True
                            
                    if(__exists):
                        __outarray.append(item)
        
                    
        except:
            __outarray = None

        return __outarray







    """
        CREDENTIAL = {
            'host': "ip_address",
            'user': "username",
            'pass': "password",
            'port': api_port
        }


        SOURCE = "/ip/firewall/nat"

        RULE = {
            'chain':'dstnat',
            'action':'dst-nat',
            'protocol':'tcp',
            'to-addresses':'198.0.0.1',
            'to-ports':'8080',
            'dst-address':'192.160.0.12',
            'dst-port':'80'
        }
        
        Mikrotik.add(CREDENTIAL, SOURCE, RULE)
    """
    def add(credentials, resource, args) -> bool :
        
        if not (RouterOS.__isvalidCredentials(credentials)):
            return False

        try:
            mk = RouterOS(credentials['host'], credentials['user'], credentials['pass'], credentials['port'])

            if(mk.__login()):

                mk.__source(resource).add(**args)
            else:
                return False
            
            mk.__logout()

            return True
        except:
            return False






    """
        CREDENTIAL = {
            'host': "ip_address",
            'user': "username",
            'pass': "password",
            'port': api_port
        }


        SOURCE = "/ip/firewall/nat"
        
        Mikrotik.remove(CREDENTIAL, SOURCE, "*DB1")
    """
    def remove(credentials, resource, idrule) -> bool:


        if not (RouterOS.__isvalidCredentials(credentials)):
            return False

        try:    
            mk = RouterOS(credentials['host'], credentials['user'], credentials['pass'], credentials['port'])
            if(mk.__login()):
                mk.__source(resource).remove(idrule)

            mk.__logout()
            return True

        except Exception as Error:
            return False






    """
        CREDENTIAL = {
            'host': "ip_address",
            'user': "username",
            'pass': "password",
            'port': api_port
        }


        SOURCE = "/ip/firewall/nat"
        
        Mikrotik.remove(CREDENTIAL, SOURCE, "*DB1")

        RULE = {
            '.id' : '*2C9',
            'dst-address':'138.117.193.255',
            'dst-port':'5555'
        }
    """
    def update(credentials, resource, params) -> bool:
        
   
        if not (RouterOS.__isvalidCredentials(credentials)):
            return False
 
        try:
            mk = RouterOS(credentials['host'], credentials['user'], credentials['pass'], credentials['port'])

            if(mk.__login()):

                mk.__source(resource).update(**params)
            else:
                return False
            
            mk.__logout()
            return True
        except:
            return False



    """
        CREDENTIAL = {
            'host': "ip_address",
            'user': "username",
            'pass': "password",
            'port': api_port
        }


        SOURCE = "/ip/firewall/nat"

        ARGS = {
            '.id': '*2D5'
        }

        get(CREDENTIAL, SOURCE, ARGS)
        
    """
    def get(credential, resource, args, results='all') -> dict:


        __outget = RouterOS.get_raw('dict', credential, resource, args)

        if(__outget is not None):

            if(len(__outget) > 0):

                if(results == 'all'):
                    return __outget
                
                if(results == 'one'):
                    return __outget[0]

        return None







    """
        CREDENTIAL = {
            'host': "ip_address",
            'user': "username",
            'pass': "password",
            'port': api_port
        }


        SOURCE = "/ip/firewall/nat"

        ARGS = {
            'chain':'dstnat',
            'action':'dst-nat',
            'protocol':'tcp',
            'to-addresses':'100.78.254.3',
            'dst-address':'198.0.0.1',
            'to-ports':'3122',
            'dst-port':'2000'
        }

        exist(CREDENTIAL, SOURCE, ARGS)
        
    """
    def exist(credentials, resource, rule) -> dict:

        if not (RouterOS.__isvalidCredentials(credentials)):
            return False

        
        for __item in RouterOS.get_raw('key', credentials, resource, rule.keys()):
            if(RouterOS.similar_dict(__item, rule)):
                return True

        return False
