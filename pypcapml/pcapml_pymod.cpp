/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "sampler.hpp"

/* SamplerState - pcapML sample group instance.
 *
 * enum_index: next enumeration index to yield
 * sampler: PcapMLSampler handle
 *
*/
typedef struct {
    PyObject_HEAD
    Py_ssize_t enum_index;
    Sampler sampler;
} SamplerState;

static PyTypeObject PcapmlSampleType = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static PyStructSequence_Field pcapml_sample_fields[] = {
    {"index", "Index value"},
    {"sid", "Sample ID"},
    {"label", "Sample label"},
    {"ts", "Packet timestamp"},
    {"raw_bytes", "Packet bytes"},
    {NULL}
};

static PyStructSequence_Desc pcapml_sample_desc = {
    "pcapml.feature_explorer",
    NULL,
    pcapml_sample_fields,
    5
};

static PyObject *
sampler_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    
    char *filename = NULL;
    Sampler s;
    
    /* Parse arguments */
    if(!PyArg_ParseTuple(args, "s", &filename)) {
        return NULL;
    }

    SamplerState *sstate = (SamplerState *)type->tp_alloc(type, 0);
    
    if (!sstate)
        return NULL;
    
    s.open_pcapng(filename);
    sstate->enum_index = 0;
    sstate->sampler = s;

    return (PyObject *)sstate;    
}

static void
sampler_dealloc(SamplerState *sstate)
{
    Py_TYPE(sstate)->tp_free(sstate);
}

static PyObject *
sampler_next(SamplerState *sstate)
{
    Sample *s;
    uint64_t i;

    while(1) {
            
            s = sstate->sampler.get_next_sample();
            if (s == NULL) {
                
                return NULL;
            }

            PyObject *resultlst = PyList_New(s->get_pkts().size());

            PyTypeObject *PcapmlSampleType = PyStructSequence_NewType(&pcapml_sample_desc);
            Py_INCREF(PcapmlSampleType);

            for (i = 0; i < s->get_pkts().size(); ++i) {

                PyObject *PcapmlSample = PyStructSequence_New(PcapmlSampleType);
                PyStructSequence_SET_ITEM(PcapmlSample, 0, Py_BuildValue("i", sstate->enum_index));
                PyStructSequence_SET_ITEM(PcapmlSample, 1, Py_BuildValue("k", s->get_sid()));
                PyStructSequence_SET_ITEM(PcapmlSample, 2, Py_BuildValue("s", s->get_label().c_str()));
                PyStructSequence_SET_ITEM(PcapmlSample, 3, Py_BuildValue("k", s->get_pkt_ts()[i]));
                PyStructSequence_SET_ITEM(PcapmlSample, 4, Py_BuildValue("y#", s->get_pkts()[i], s->get_pkt_lens()[i]));

                PyList_SET_ITEM(resultlst, i, PcapmlSample);
            }

            sstate->enum_index++;
            return resultlst;
    }

}

PyTypeObject PySampler_Type = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "pcapml_FE",                     /* tp_name */
    sizeof(SamplerState),            /* tp_basicsize */
    0,                               /* tp_itemsize */
    (destructor)sampler_dealloc,     /* tp_dealloc */
    0,                               /* tp_print */
    0,                               /* tp_getattr */
    0,                               /* tp_setattr */
    0,                               /* tp_reserved */
    0,                               /* tp_repr */
    0,                               /* tp_as_number */
    0,                               /* tp_as_sequence */
    0,                               /* tp_as_mapping */
    0,                               /* tp_hash */
    0,                               /* tp_call */
    0,                               /* tp_str */
    0,                               /* tp_getattro */
    0,                               /* tp_setattro */
    0,                               /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,              /* tp_flags */
    0,                               /* tp_doc */
    0,                               /* tp_traverse */
    0,                               /* tp_clear */
    0,                               /* tp_richcompare */
    0,                               /* tp_weaklistoffset */
    PyObject_SelfIter,               /* tp_iter */
    (iternextfunc)sampler_next,      /* tp_iternext */
    0,                               /* tp_methods */
    0,                               /* tp_members */
    0,                               /* tp_getset */
    0,                               /* tp_base */
    0,                               /* tp_dict */
    0,                               /* tp_descr_get */
    0,                               /* tp_descr_set */
    0,                               /* tp_dictoffset */
    0,                               /* tp_init */
    PyType_GenericAlloc,             /* tp_alloc */
    sampler_new,                     /* tp_new */
};


static struct PyModuleDef pcapmlmodule = {
    PyModuleDef_HEAD_INIT,
    "pcapml_FE",
    "Python module for the pcapML feature exploration library",
    -1,
};

PyMODINIT_FUNC
PyInit_pcapml_FE(void)
{
    PyObject *module = PyModule_Create(&pcapmlmodule);
    PyStructSequence_InitType(&PcapmlSampleType, &pcapml_sample_desc);

    if (!module)
        return NULL;

    if (PyType_Ready(&PySampler_Type) < 0)
        return NULL;
    Py_INCREF((PyObject *)&PySampler_Type);
    PyModule_AddObject(module, "sampler", (PyObject *)&PySampler_Type);

    return module;
}
