function goBack() {
  try {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  } catch (e) {
    window.close();
  }
}

function closeTab() {
  try {
    window.close();
  } catch (e) {
    window.location.href = 'about:blank';
  }
}

function proceedAnyway(url) {
  try {
    window.location.href = url;
  } catch (e) {
    window.open(url, '_blank');
  }
}

function submitFormAnyway(form) {
  try {
    if (form && form.submit) {
      form.submit();
    }
  } catch (e) {
    console.log('Form submission blocked');
  }
}

window.goBack = goBack;
window.closeTab = closeTab;
window.proceedAnyway = proceedAnyway;
window.submitFormAnyway = submitFormAnyway;