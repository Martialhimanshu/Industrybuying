import uuid

from django.db import models
from django.conf import settings
from django.utils.crypto import get_random_string

from restAPI.models import TimeStampedModel

def get_random_string_value():
    return get_random_string(length=32)


class DeviceType(object):
    IOS = 1
    ANDROID = 2
    WEB = 3


class ApiApp(TimeStampedModel):
    IB_PLATFORM_TYPE = (
        (DeviceType.IOS, "Ios"), (DeviceType.ANDROID, "Android"),
        (DeviceType.WEB, "Web")
    )

    app_name = models.CharField(max_length=40)
    app_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, db_index=True)
    api_secret_key = models.CharField(max_length=32, default=get_random_string_value, editable=False)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    active = models.BooleanField(default=True)
    platform = models.SmallIntegerField(choices=IB_PLATFORM_TYPE)
    domain_url = models.URLField(default=None, null=True, blank=True)

    def __unicode__(self):
        return self.app_name
