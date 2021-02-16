from test.BaseCase import BaseCase


class TestGetTaxonomyCategories(BaseCase):

    @BaseCase.login
    def test_ok(self, token):
        self.db.insert({"name": "CAT1"}, self.db.tables["TaxonomyCategory"])
        self.db.insert({"name": "CAT2"}, self.db.tables["TaxonomyCategory"])

        response = self.application.get('/taxonomy/get_taxonomy_categories',
                                        headers=self.get_standard_header(token))

        self.assertEqual(200, response.status_code)
        self.assertEqual([
            {'is_company_category': 0, 'name': 'CAT1'},
            {'is_company_category': 0, 'name': 'CAT2'}
        ], response.json)

    @BaseCase.login
    def test_ok_empty(self, token):
        response = self.application.get('/taxonomy/get_taxonomy_categories',
                                        headers=self.get_standard_header(token))

        self.assertEqual(200, response.status_code)
        self.assertEqual([], response.json)