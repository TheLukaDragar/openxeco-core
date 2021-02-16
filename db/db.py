from sqlalchemy import MetaData
from sqlalchemy.ext.declarative import declarative_base
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, and_
import datetime


class SA(SQLAlchemy):
    def apply_pool_defaults(self, app, options):
        SQLAlchemy.apply_pool_defaults(self, app, options)
        options["pool_pre_ping"] = True
        options["pool_recycle"] = 60


class DB:
    engine = None

    def __init__(self, application):
        self.instance = SA(application)
        self.instance.init_app(application)

        self.session = self.instance.session
        self.engine = self.instance.engine

        self.tables = {}
        self.base = declarative_base()
        self.base.metadata = MetaData(bind=self.instance)

        for table in self.engine.table_names():
            attr = {'__tablename__': table, '__table_args__': {'autoload': True, 'autoload_with': self.engine}}
            self.tables[table] = type(table, (self.base,), attr)

    ###############
    # GLOBAL      #
    ###############

    def merge(self, data, table, commit=True):
        if type(data) == dict:
            data = table(**data)
            data = self.session.merge(data)
        elif type(data) == list:
            for row in data:
                if type(row) == dict:
                    row = table(**row)
                self.session.merge(row)
        else:
            data = self.session.merge(data)

        if commit:
            self.session.commit()

        return data

    def insert(self, data, table, commit=True):
        if type(data) == dict:
            data = table(**data)
            self.session.add(data)
        else:
            for row in data:
                if type(row) == dict:
                    row = table(**row)
                self.session.add(row)

        if commit:
            self.session.commit()

        return data

    def delete(self, table, filters=None, commit=True):
        if filters is None:
            # We don't take the risk to have to filter on delete, truncate() is made for that
            return
        else:
            q = self.session.query(table)
            for attr, value in filters.items():
                if type(value) == list:
                    q = q.filter(getattr(table, attr).in_(value))
                else:
                    q = q.filter(getattr(table, attr) == value)
            q.delete()

            if commit:
                self.session.commit()

    def delete_by_id(self, id, table):
        self.session.query(table).filter(table.id == id).delete()
        self.session.commit()

    def truncate(self, table):
        self.session.query(table).delete()
        self.session.commit()

    def get(self, table, filters={}, entities=None):
        q = self.session.query(table)

        if entities is not None:
            q = q.with_entities(*entities)

        for attr, value in filters.items():
            if type(value) == list:
                q = q.filter(getattr(table, attr).in_(value))
            else:
                q = q.filter(getattr(table, attr) == value)

        return q.all()

    def get_count(self, table, filters={}):
        q = self.session.query(table)
        for attr, value in filters.items():
            if type(value) == list:
                q = q.filter(getattr(table, attr).in_(value))
            else:
                q = q.filter(getattr(table, attr) == value)
        return q.count()

    def get_by_id(self, id, table):
        return self.session.query(table).filter(table.id == id).one()

    ###############
    # UTILS       #
    ###############

    @staticmethod
    def are_objects_equal(a, b, table):
        for c in table.__table__.columns.keys():
            if getattr(a, c) != getattr(b, c):
                return False
        return True

    ###############
    # COMPANY     #
    ###############

    def get_filtered_companies(self, filters={}, entities=None):

        query = self.session.query(self.tables["Company"])

        if entities is not None:
            query = query.with_entities(*entities)

        if "name" in filters and filters['name'] is not None:
            name = func.lower(filters['name'])
            query = query.filter(func.lower(self.tables["Company"].name).like("%" + name + "%"))

        if "type" in filters and filters['type'] is not None:
            if type(filters['type']) == list:
                query = query.filter(self.tables["Company"].type.in_(filters['type']))
            else:
                query = query.filter(self.tables["Company"].type == filters['type'])

        if "startup_only" in filters and filters['startup_only'] == "true":
            query = query.filter(self.tables["Company"].is_startup.is_(True))

        if "corebusiness_only" in filters and filters['corebusiness_only'] == "true":
            query = query.filter(self.tables["Company"].is_cybersecurity_core_business.is_(True))

        if "taxonomy_values" in filters:
            taxonomy_values = [int(value_id) for value_id in filters["taxonomy_values"].split(",") if value_id.isdigit()]

            if len(taxonomy_values) > 0:
                tch = taxonomy_values

                while len(tch) > 0:
                    taxonomy_values = tch
                    tch = self.session\
                        .query(self.tables["TaxonomyValueHierarchy"]) \
                        .filter(self.tables["TaxonomyValueHierarchy"].parent_value.in_(tch)).all()
                    tch = [t.child_value for t in tch]

                companies_filtered_by_taxonomy = self.session \
                    .query(self.tables["TaxonomyAssignment"]) \
                    .with_entities(self.tables["TaxonomyAssignment"].company) \
                    .distinct(self.tables["TaxonomyAssignment"].company) \
                    .filter(self.tables["TaxonomyAssignment"].taxonomy_value.in_(taxonomy_values)) \
                    .subquery()

                query = query.filter(self.tables["Company"].id.in_(companies_filtered_by_taxonomy))

        return query.all()

    ###############
    # ARTICLE     #
    ###############

    def get_filtered_articles(self, filters={}):

        query = self.session.query(self.tables["Article"])

        if "title" in filters and filters['title'] is not None:
            title = func.lower(filters['title'])
            query = query.filter(func.lower(self.tables["Article"].title).like("%" + title + "%"))

        if "status" in filters:
            query = query.filter(self.tables["Article"].status == filters["status"])

        if "type" in filters:
            types = filters["type"].split(",")
            query = query.filter(self.tables["Article"].type.in_(types))

        if "media" in filters:
            query = query.filter(self.tables["Article"].media.in_(["ALL", filters["media"]]))

        if "public_only" in filters and filters["public_only"] == "true":
            query = query.filter(self.tables["Article"].handle != None)
            query = query.filter(self.tables["Article"].status == "PUBLIC")
            query = query.filter(self.tables["Article"].publication_date <= datetime.date.today())

        if "taxonomy_values" in filters:
            tmp_taxonomy_values = [value_id for value_id in filters["taxonomy_values"].split(",")]
            taxonomy_values = []

            for tv in tmp_taxonomy_values:
                if tv.isdigit():
                    taxonomy_values.append(int(tv))
                else:
                    db_values = self.get(self.tables["TaxonomyValue"], {"name": tv})
                    taxonomy_values += [v.id for v in db_values]

            if len(taxonomy_values) > 0:
                tch = taxonomy_values

                while len(tch) > 0:
                    taxonomy_values = tch
                    tch = self.session \
                        .query(self.tables["TaxonomyValueHierarchy"]) \
                        .filter(self.tables["TaxonomyValueHierarchy"].parent_value.in_(tch)).all()
                    tch = [t.child_value for t in tch]

                article_filtered_by_taxonomy = self.session \
                    .query(self.tables["ArticleTaxonomyTag"]) \
                    .with_entities(self.tables["ArticleTaxonomyTag"].article) \
                    .distinct(self.tables["ArticleTaxonomyTag"].article) \
                    .filter(self.tables["ArticleTaxonomyTag"].taxonomy_value.in_(taxonomy_values)) \
                    .subquery()

                query = query.filter(self.tables["Article"].id.in_(article_filtered_by_taxonomy))

        query = query.order_by(self.tables["Article"].publication_date.desc())

        return query.all()

    def get_tags_of_article(self, article_id):
        companies_filtered_by_taxonomy = self.session \
            .query(self.tables["ArticleTaxonomyTag"]) \
            .with_entities(self.tables["ArticleTaxonomyTag"].taxonomy_value) \
            .filter(self.tables["ArticleTaxonomyTag"].article == article_id) \
            .subquery()

        return self.session \
            .query(self.tables["TaxonomyValue"]) \
            .filter(self.tables["TaxonomyValue"].id.in_(companies_filtered_by_taxonomy)) \
            .all()

    ###############
    # WORKFORCE   #
    ###############

    def get_latest_workforce(self, company_ids=None):
        sub_query = self.session.query(
            self.tables["Workforce"].company,
            func.max(self.tables["Workforce"].date).label('maxdate')
        ).group_by(self.tables["Workforce"].company).subquery('t2')

        query = self.session.query(self.tables["Workforce"])

        if company_ids is not None:
            query = query.filter(self.tables["Workforce"].company.in_(company_ids))

        query = query.join(
            sub_query,
            and_(
                self.tables["Workforce"].company == sub_query.c.company,
                self.tables["Workforce"].date == sub_query.c.maxdate
            ))

        return query.all()

    ###############
    # TAXONOMY    #
    ###############

    def get_value_hierarchy(self, parent_category, child_category):
        parent_sub_query = self.session.query(self.tables["TaxonomyValue"].id) \
            .filter(self.tables["TaxonomyValue"].category == parent_category)

        child_sub_query = self.session.query(self.tables["TaxonomyValue"].id) \
            .filter(self.tables["TaxonomyValue"].category == child_category)

        query = self.session.query(self.tables["TaxonomyValueHierarchy"]) \
            .filter(self.tables["TaxonomyValueHierarchy"].parent_value.in_(parent_sub_query)) \
            .filter(self.tables["TaxonomyValueHierarchy"].child_value.in_(child_sub_query)) \

        return query.all()