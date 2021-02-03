import xlsxwriter


class DataWriter:
    """
    A class for write CVE search results to excel.
    """
    def __init__(self):
        """
        Constructor
        """
        self.row = 0
        # Create a workbook and add a worksheet.
        self.workbook = xlsxwriter.Workbook('results.xlsx')
        self.worksheet = self.workbook.add_worksheet()

    def write_excel(self, data, has_title):
        """
        Write search results to excel

        :param data: Search results to write.
        :param has_title: If has title is True, set col to 0. Write date at the beginning.
        :return:
        """
        col = 2
        if has_title:
            col = 0
        # Iterate over the data and write it out row by row.
        for item in data:
            self.worksheet .write(self.row, col, item)
            col += 1
        self.row += 1

    def close(self):
        """
        Close the excel

        :return:
        """
        self.workbook.close()


