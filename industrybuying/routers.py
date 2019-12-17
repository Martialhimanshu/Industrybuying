from rest_framework.routers import DefaultRouter
from restAPI.api.viewsets import DataAPIViewSet

router = DefaultRouter()
router.register('data', DataAPIViewSet)
