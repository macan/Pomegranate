# Pomegranate File System Documentation

<a href="http://github.com/macan/Pomegranate"><img src="https://github.com/macan/macan.github.com/raw/master/png/Pomegranate_logo.png" /></a>

It **is** a distributed file system, but **not only** a file system!

[Wiki Page](http://github.com/macan/Pomegranate/wiki)

## Introduction

Pomegranate File System (abbr. PFS) is originally proposed for large scale
small file access. It contains many optimizations for small objects.

* Automatic small file aggregation based on file system directory
* Tabular directory model, support metadata deduplication
* Automatic migrating file creations in a cluster
* Metadata store and small file data store is designed for flash device
* Support POSIX, REST interface
* Has C/Python bindings

### Architecture

To exploit fast storage devices to accelerate small file performace, e.g. SSD,
PFS adopts a 3-tier storage architecture. 

The first tier is **memory caching** layer, which is used for metadata caching
to reduce metadata latency. Metadata latency has significant impacts on small
file I/O latency. Decreasing metadata latency can efficient improve the small
file performace.

The second tier is **flash caching** layer, which is used for durability of
metadata and small data. Flash device has lower I/O latency. Thus, it is
suitable for small data access.

The third tier is **disk store** layer, which is designed for longer
durability of all data. It use data replication for data reliability and
deduplication for efficient space consumption.

### Tabular Directory Model

In many Web 2.0 applications, objects (e.g. photos, videos, docs, ...) are
saved in several different forms. For example, in a photo gallery web site,
photoes that updated by users are transformed to several resolutions. These
different object forms that derived from the same (original) object contains
almost the same metadata. Thus, if we save these different forms into
different files, then we would have many metadata duplication in distributed
file system. We define this issue as **N-Form** issue.

To overcome the above N-Forms issue, we propose to introduce powerful
directory model to traditional file system. In PFS, we use tabular directory
model to keep file system metadata. With one file name, users can save many
different object forms in different columns' cells. File metadata is a special
table column of the directory table.

By adopting tabular directory model, the metadata duplication of N-Form issue
can be overcomed. Besides this benefit, the new directory model grouped the
file data which has the same property or usage purpose in the same
column. Thus, we can do more efficient file placements and aggregations.

### File Aggregation

In Web 2.0 applications, objects are mainly in small size. For example, social
network web pages contain many small sized photoes and short video
segments. The typical size of these objects are less than 10MB. Many
traditional distributed file systems are designed for HPC applications, which
targets at large file I/O optimization. Thus, for small files, many of these
I/O optimizations are **not** as efficient as that for large files.

To optimize small file I/O, we propose to do file aggregation based on tabular
directory model. For files that in the same directory, we do file aggregations
automatically. For each directory column, we generate an aggregated large
file. File content is cached and then write sequentially to low level
SSD. File aggregation can maximally utilize low level I/O bandwidth.

### Extendible Metadata Service

There are so many objects to store in Web 2.0 applications. User generated
objects, such as uploaded photoes, videos, documents, are tremendous. To
manage these massive objects in a file system means that we need a expandable
metadata service.

In PFS, we exploid the extendible hash technology to distribute file metadata
across many cache servers. Metadata can migrate from one server to other
server when there are too many cached file entries. The cache server can be
add in or remove out at any time with little latency. File metadata is
redistributed automatically on server changes.

## Development Cycle

A new OBJECT STORE LAYER for large files is under developing.

