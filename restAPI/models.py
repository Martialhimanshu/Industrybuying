from django.db import models

# Create your models here.


class TimeStampedModel(models.Model):
    """
       An abstract base class model that provides self-updating
       ``created`` and ``modified`` fields.
       """
    created_at = models.DateTimeField(_('created'), auto_now_add=True, editable=False)
    modified_at = models.DateTimeField(_('modified'), auto_now=True)

    class Meta:
        abstract = True


class Content(TimeStampedModel):
    msg = models.CharField(max_length=512, null=True, blank=True)
    truth = models.CharField(max_length=64, null=True, blank=True)
    google = models.CharField(max_length=128, null=True, blank=True)
    cube = models.CharField(max_length=64, null=True, blank=True)
    google_spam = models.FloatField(blank=True, null=True)
    google_not_spam = models.FloatField(blank=True, null=True)
    ibm = models.CharField(max_length=64, null=True, blank=True)
    ibm_spam = models.FloatField(blank=True, null=True)
    ibm_not_spam = models.FloatField(blank=True, null=True)



