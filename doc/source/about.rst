#####################
About These Documents
#####################

These documents are generated from `reStructuredText`_ sources by `Sphinx`_, a
document processor specifically written for the Python documentation.

.. _reStructuredText: http://docutils.sourceforge.net/rst.html
.. _Sphinx: http://sphinx-doc.org/


Building The Documentation
**************************

To build the keepalived documentation, you will need to have a recent version
of Sphinx installed on your system.  Alternatively, you could use a python
virtualenv.

From the root of the repository clone, run the following command to build the
documentation in HTML format::

    cd keepalived-docs
    make html

For PDF, you will also need ``docutils`` and various ``texlive-*`` packages for
converting reStructuredText to LaTex and finally to PDF::

    pip install docutils
    cd keepalived-docs
    make latexpdf

Alternatively, you can use the ``sphinx-build`` command that comes with the
Sphinx package::

    cd keepalived-docs
    sphinx-build -b html . build/html

.. todo::
   make latexpdf needs pdflatex provided by texlive-latex on RHEL6 and
   texlive-latex-bin-bin on Fedora21

.. todo::
   make linkcheck to check for broken links
