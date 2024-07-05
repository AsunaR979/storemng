"""
GeneralQuery实现数据库的通用查询以及序列化为json返回
"""
import logging
from django.http import JsonResponse
from web_manage.common.utils import WebPagination, param_error


logger = logging.getLogger(__name__)


class GeneralQuery(object):

    def get_object_list(self, request, model, serializer, **kwargs):
        try:
            page_size = kwargs.get('page_size', None)
            page = WebPagination()
            if page_size:
                page.page_size = page_size
                kwargs.pop('page_size')
            contain = kwargs.get('contain', None)
            logger.debug("table:%s, query conditions:%s", model._meta.db_table, kwargs)
            # 默认模糊查询条件是and，如果需要使用or，则在外层组合好，通过contain字段传递进来
            if contain:
                logger.debug("get contain query filter:%s", contain)
                kwargs.pop('contain')
                query_set = model.objects.filter(**kwargs).filter(contain)
            else:
                query_set = model.objects.filter(**kwargs)
            instance = page.paginate_queryset(queryset=query_set, request=request, view=self)
            ser = serializer(instance=instance, many=True, context={'request': request})
            return page.get_paginated_response(ser.data)
        except Exception as e:
            logger.error("get all data from table:%s error:%s", model ._meta.db_table, e)
            raise e


    def get_object(self, request, model, serializer, **kwargs):
        try:
            ret = {
                'code': 0,
                "message": "success",
                "data": None
            }
            logger.debug("table:%s, query conditions:%s", model ._meta.db_table, kwargs)
            query_set = model.objects.filter(**kwargs).first()
            if query_set:
                ser = serializer(query_set, context={'request': request})
                ret['data'] = ser.data
                return JsonResponse(ret)
            else:
                return JsonResponse(ret)
        except Exception as e:
            logger.error("get single data from table:%s error:%s", model ._meta.db_table, e)
            raise e

    def get_query_kwargs(self, request, **kwargs):
        info = request.GET.dict()
        search_type = info.get('searchtype', 'all')
        try:
            info.pop('searchtype')
        except:
            pass
        # 模糊查询和精确查询需要参数
        if search_type != 'all' and not info:
            return param_error("ParamError")

        for key, value in info.items():
            # 分页查询时，需要page关键词，数据库如果有page字段，则该字段的条件会被忽略
            if 'page' == key:
                continue
            if 'all' == search_type:
                kwargs[key] = value
            elif 'contain' == search_type:
                if 'page_size' == key:
                    kwargs[key] = value
                    continue
                kwargs[key + '__icontains'] = value
            elif 'single' == search_type:
                kwargs[key] = value
            else:
                pass
        kwargs['deleted'] = False
        kwargs['search_type'] = search_type
        return kwargs

    def model_query(self, request, model, serializer, query_dict, contain=None):
        """
        :param request:
            searchtype: 'all/single/contain'
            key: the search key, 'name' or 'uuid' is the most situation
            value: the value of the search key
        :param model: the table model
        :param serializer: the serilizer of the model
        :param query_dict: the extra conditions of the query
        :param contain: the contain search of or, default is and
        :return:
        """
        try:
            # info = request.GET.dict()
            # search_type = info.get('searchtype', 'all')
            # try:
            #     info.pop('searchtype')
            # except:
            #     pass
            # # 模糊查询和精确查询需要参数
            # if search_type != 'all' and not info:
            #     return param_error("ParamError")
            #
            # for key, value in info.items():
            #     # 分页查询时，需要page关键词，数据库如果有page字段，则该字段的条件会被忽略
            #     if 'page' == key:
            #         continue
            #     if 'all' == search_type:
            #         kwargs[key] = value
            #     elif 'contain' == search_type:
            #         if 'page_size' == key:
            #             kwargs[key] = value
            #             continue
            #         kwargs[key + '__icontains'] = value
            #     elif 'single' == search_type:
            #         kwargs[key] = value
            #     else:
            #         pass
            # kwargs['deleted'] = False
            try:
                search_type = query_dict.pop('search_type')
            except:
                search_type = 'all'
            if contain:
                query_dict['contain'] = contain
            if 'all' == search_type:
                return self.get_object_list(request, model, serializer, **query_dict)
            elif 'contain' == search_type:
                return self.get_object_list(request, model, serializer, **query_dict)
            elif 'single' == search_type:
                return self.get_object(request, model, serializer, **query_dict)
            else:
                return param_error("ParamError")
        except Exception as e:
            logger.error("get request failed:%s", e, exc_info=True)
            return param_error("SystemError")
