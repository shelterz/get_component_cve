import re
from znet import Network, RespType
try:
    from BeautifulSoup import BeautifulSoup
except ImportError:
    from bs4 import BeautifulSoup


class CveGetter:
    """
    A class for getting CVE information from website NVD(https://nvd.nist.gov)
    """
    def __init__(self):
        self.net = Network()

    def check_product_exists(self, product):
        """
        Check if the product information exists in NVD

        :param product: Product name
        :return: If product exists, return True
        """
        url = "https://nvd.nist.gov/rest/public/cpe/products"
        params = {'serviceType': 'productList', 'startsWith': product}

        r = self.net.request(url, params, RespType.JSON)
        # If product exists, component dict not empty
        if not r['components']:
            return False
        return True

    def get_product_vendors(self, product):
        """
        Get the supported vendors of product.

        :param product: Product name
        :return: Supported vendor list
        """
        url = 'https://nvd.nist.gov/rest/public/cpe/vendors'
        params = {'serviceType': 'vendors', 'product': product}
        vendors = []
        r = self.net.request(url, params, RespType.JSON)
        components = r['components']
        if components:
            for c in components:
                vendors.append(c['componentName'])
        return vendors

    def get_vendor_supported_versions(self, product, vendor, version_prefix):
        """
        Get the supported versions based on given product and vendor.

        :param product: Product name
        :param vendor: Vendor name
        :param version_prefix: Version string prefix. Full version string also support
        :return: Version list
        """
        url = 'https://nvd.nist.gov/rest/public/cpe/versions'
        params = {
            'serviceType': 'versionList',
            'product': product,
            'vendor': vendor,
            'startsWith': version_prefix
        }
        versions = []
        r = self.net.request(url, params, RespType.JSON)
        components = r['components']
        if components:
            for c in components:
                uri = c['cpeUri']
                version = uri.split(":")[-1]
                versions.append(version)
        return versions

    def get_specific_search_results(self, vendor, product, version, index):
        """
        Get CVE search results.

        :param vendor: Vendor name
        :param product:  Product name
        :param version: Version string
        :param index: Page index. It only show 20 item in one page.
        :return:
        """
        url = 'https://nvd.nist.gov/vuln/search/results'
        # Convert params to uri params
        cpe_vendor = 'cpe:/:' + vendor
        cpe_product = 'cpe:/::' + product
        cpe_version = 'cpe:/:' + vendor + ':' + product + ':' + version

        params = {
            'form_type': 'Advanced',
            'results_type': 'overview',
            'search_type': 'all',
            'cpe_vendor': cpe_vendor,
            'cpe_product': cpe_product,
            'cpe_version': cpe_version,
            'startIndex': index
        }

        r = self.net.request(url, params, RespType.HTML)
        return r

    def get_cve_count(self, html):
        """
        Parse the CVE count from html content.

        :param html: Input html get from function `get_specific_search_results`
        :return: CVE count number
        """
        soup = BeautifulSoup(html, features="html.parser")
        cve_count = soup.body.find('strong', attrs={'data-testid': 'vuln-matching-records-count'}).text
        return cve_count

    def get_cve_info(self, html):
        """
        Parse the search results from html content.

        :param html: Input html get from function `get_specific_search_results`
        :return: @SearchResults list
        """
        soup = BeautifulSoup(html, features="html.parser")
        search_results = []
        for i in soup.tbody.find_all('tr', {'data-testid': True}):
            name = i.find('th').text
            desc = i.find('p').text
            date = i.find('span', {'data-testid': re.compile(r"vuln-published-on-*")}).text
            cvss3 = i.find('span', {'id': 'cvss3-link'})
            cvss2 = i.find('span', {'id': 'cvss2-link'})
            if not cvss3:
                cvss = 'V3.x:(not available)'
            else:
                cvss = cvss3.text.strip()
            # Add separator between two cvss
            cvss += '/'
            if not cvss2:
                cvss += 'V2.x:(not available)'
            else:
                cvss += cvss2.text.strip()
            search_results.append(SearchResults(name, desc, date, cvss))
        return search_results


class SearchResults:
    """
    Search results object.
    """
    def __init__(self, name, desc, date, cvss):
        self.name = name
        self.desc = desc
        self.date = date
        self.cvss = cvss
