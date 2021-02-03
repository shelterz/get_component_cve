import requests
from enum import Enum, unique

@unique
class RespType(Enum):
    JSON = 0
    HTML = 1


class Network:
    """
    A class for http request.
    """

    def request(self, url, params, resp_type):
        """
        Send http request.

        :param url: Http url.
        :param params: Http get params.
        :param resp_type: @RespType
        :return: Http response.
        """
        r = requests.get(url, params=params)
        if resp_type == RespType.JSON:
            return r.json()
        elif resp_type == RespType.HTML:
            return r.text
