import argparse
from cve_getter import CveGetter
from data_writer import DataWriter
from zlogger import logger


def get_cve_results(product, version, writer):
    cve_getter = CveGetter()
    if not cve_getter.check_product_exists(product):
        logger.info('Product %s not exists', product)
        return
    vendors = cve_getter.get_product_vendors(product)
    for ven in vendors:
        versions = cve_getter.get_vendor_supported_versions(product, ven, version)
        if version in versions:
            logger.info('specific version found, do search')
            index = 0
            PAGE_ITEM_MAX = 20
            html = cve_getter.get_specific_search_results(ven, product, version, index)
            cve_count = cve_getter.get_cve_count(html)
            logger.info("cve count number is " + cve_count)
            # Walk pages
            item_count = int(cve_count)
            # A line to write
            data_to_write = [product, version]
            has_title = True
            while item_count > 0:
                html = cve_getter.get_specific_search_results(ven, product, version, index)
                cve_info = cve_getter.get_cve_info(html)
                index += PAGE_ITEM_MAX
                # We can only get 20 items in one page.
                item_count -= PAGE_ITEM_MAX
                for search_result in cve_info:
                    data_to_write.append(search_result.name)
                    data_to_write.append(search_result.desc)
                    data_to_write.append(search_result.date)
                    data_to_write.append(search_result.cvss)
                    writer.write_excel(data_to_write, has_title)
                    if has_title:
                        has_title = False
                    data_to_write.clear()
        else:
            logger.info('Product %s, version %s not found. supported verions %s', product, version, versions)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This a tool to fetch cve info from nvd.')
    parser.add_argument('product', help="The product name.")
    parser.add_argument('version', help="The product version.")
    args = parser.parse_args()
    cve_writer = DataWriter()
    get_cve_results(args.product, args.version, cve_writer)
    cve_writer.close()
