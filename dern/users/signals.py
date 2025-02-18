from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Requests, History

@receiver(post_save, sender=Requests)
def create_history_entry(sender, instance, **kwargs):
    """
    Signal to create a History entry when a Requests object is marked as done.
    """
    if instance.is_done:
        technicians = instance.technician.all()
        if technicians.exists():
            for tech in technicians:
                History.objects.get_or_create(
                    user=instance.user,  # Use instance.user instead of instance.user_id
                    technician=tech,
                    request=instance
                )
        else:
            History.objects.get_or_create(
                user=instance.user,  # Use instance.user instead of instance.user_id
                technician=None,
                request=instance
            )